import asyncio
from contextlib import suppress
import importlib.util
import json
import sys
import tempfile
import types
import unittest
import unittest.mock
from dataclasses import dataclass, field
from pathlib import Path


PLUGIN_DIR = Path(__file__).resolve().parents[1]
ADAPTER_PATH = PLUGIN_DIR / "adapter.py"


def wire_event(event):
    """Build the intentionally breaking structured v2 inbound shape for tests."""
    if event.get("type") != "inbound_message" or "message" in event:
        return event
    flat = dict(event)
    message = {
        "message_id_hex": flat.pop("message_id_hex"),
        "sender": {
            "account_id_hex": flat.pop("sender_account_id_hex", "44" * 32),
            "display_name": flat.pop("sender_display_name", None),
            "is_self": False,
        },
        "text": flat.pop("text", ""),
        "recorded_at": flat.pop("recorded_at", 0),
        "media": flat.pop("media", []),
    }
    reply_to_message_id_hex = flat.pop("reply_to_message_id_hex", None)
    flat["message"] = message
    if reply_to_message_id_hex:
        flat["reply_to"] = {
            "message_id_hex": reply_to_message_id_hex,
            "availability": "missing",
        }
    return flat


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
        timestamp: object = None
        media_urls: list = field(default_factory=list)
        media_types: list = field(default_factory=list)
        reply_to_message_id: str | None = None
        reply_to_text: str | None = None
        reply_to_author_id: str | None = None
        reply_to_author_name: str | None = None
        reply_to_is_own_message: bool = False
        # Quiet next-turn context prepended to the trigger text by the runner;
        # never a trigger itself. Mirrors gateway.platforms.base.MessageEvent.
        channel_context: str | None = None

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
            self._message_handler = None
            self._session_tasks = {}

        @property
        def enforces_own_access_policy(self):
            return False

        def _mark_connected(self):
            self._running = True

        def _mark_disconnected(self):
            self._running = False

        async def connect(self, *, is_reconnect: bool = False) -> bool:
            # Mirrors hermes-agent's keyword-only base signature; the gateway
            # always calls connect(is_reconnect=...), so overrides must accept
            # the keyword even when they ignore it (#836).
            raise NotImplementedError

        def build_source(self, **kwargs):
            return SessionSource(platform=self.platform, **kwargs)

        async def handle_message(self, event):
            self.events.append(event)

        def _start_session_processing(self, event, session_key, *, interrupt_event=None):
            if self._message_handler is None:
                return False
            task = asyncio.create_task(self._message_handler(event))
            self._session_tasks[session_key] = task
            return True

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
        "gateway.stream_events",
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
        self.socket_path = str(Path(self.tempdir.name) / "wn-agent.sock")
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
                    "marmot_agent_control": "marmot.agent-control.v2",
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
        self.assertEqual(requests[0]["marmot_agent_control"], "marmot.agent-control.v2")
        self.assertEqual(requests[0]["type"], "send_final")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)
        self.assertEqual(requests[0]["group_id_hex"], "22" * 32)
        self.assertEqual(requests[0]["reply_to_message_id_hex"], "33" * 32)
        # Optional on the wire: the key is omitted when not supplied.
        self.assertNotIn("idempotency_key", requests[0])

    async def test_send_final_includes_idempotency_key_only_when_supplied(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "final_sent",
                    "message_ids_hex": ["aa"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        await client.send_final("11" * 32, "22" * 32, "hello", idempotency_key="key-1")
        # Blank/whitespace keys are treated as absent so they never serialize.
        await client.send_final("11" * 32, "22" * 32, "hello", idempotency_key="   ")
        await client.send_final("11" * 32, "22" * 32, "hello")

        self.assertEqual(requests[0]["idempotency_key"], "key-1")
        self.assertNotIn("idempotency_key", requests[1])
        self.assertNotIn("idempotency_key", requests[2])

    async def test_send_media_includes_idempotency_key_only_when_supplied(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "final_sent",
                    "message_ids_hex": ["44" * 32],
                    "maintenance_disposition": "not_required",
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)
        attachment = [{"path": "/tmp/a.png", "media_type": "image/png", "file_name": "a.png"}]

        await client.send_media("11" * 32, "22" * 32, attachment, idempotency_key="media-key-1")
        await client.send_media("11" * 32, "22" * 32, attachment, idempotency_key="  ")
        await client.send_media("11" * 32, "22" * 32, attachment)

        self.assertEqual(requests[0]["idempotency_key"], "media-key-1")
        self.assertNotIn("idempotency_key", requests[1])
        self.assertNotIn("idempotency_key", requests[2])

    async def test_send_media_waits_for_terminal_response_beyond_generic_timeout(self):
        publishes = 0

        async def handler(reader, writer):
            nonlocal publishes
            request = await read_json_line(reader)
            self.assertEqual(request["type"], "send_media")
            await asyncio.sleep(0.05)
            publishes += 1
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "final_sent",
                    "message_ids_hex": ["44" * 32],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)

        response = await client.send_media(
            "11" * 32,
            "22" * 32,
            [{"path": "/tmp/a.png", "media_type": "image/png", "file_name": "a.png"}],
            idempotency_key="media-key-1",
        )

        self.assertEqual(response["message_ids_hex"], ["44" * 32])
        self.assertEqual(publishes, 1)

    def test_send_in_progress_error_remains_retryable(self):
        with self.assertRaises(self.adapter.AgentControlError) as raised:
            self.adapter.MarmotAgentControlClient._raise_if_error(
                {
                    "type": "error",
                    "code": "send_in_progress",
                    "message": "matching send is still in progress",
                }
            )

        self.assertEqual(raised.exception.code, "send_in_progress")
        self.assertTrue(raised.exception.retryable)

    async def test_timeline_reads_write_exact_message_and_cursor_requests(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            if request["type"] == "timeline_message_get":
                response = {
                    "type": "timeline_message",
                    "account_id_hex": request["account_id_hex"],
                    "group_id_hex": request["group_id_hex"],
                    "message_id_hex": request["message_id_hex"],
                    "message": None,
                }
            else:
                response = {
                    "type": "timeline_page",
                    "account_id_hex": request["account_id_hex"],
                    "group_id_hex": request["group_id_hex"],
                    "messages": [],
                    "has_more_before": False,
                    "has_more_after": False,
                }
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    **response,
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)
        await client.timeline_message_get("11" * 32, "22" * 32, "33" * 32)
        await client.timeline_list(
            "11" * 32,
            "22" * 32,
            before={"recorded_at": 42, "message_id_hex": "44" * 32},
            limit=500,
        )

        self.assertEqual(requests[0]["type"], "timeline_message_get")
        self.assertEqual(requests[0]["message_id_hex"], "33" * 32)
        self.assertEqual(requests[1]["type"], "timeline_list")
        self.assertEqual(
            requests[1]["before"],
            {"recorded_at": 42, "message_id_hex": "44" * 32},
        )
        self.assertIsNone(requests[1]["after"])
        self.assertFalse(requests[1]["before_inclusive"])
        self.assertEqual(requests[1]["limit"], 50)

    async def test_stream_begin_includes_parent_message_id_only_when_supplied(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": [],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        await client.stream_begin(
            "11" * 32,
            "22" * 32,
            parent_message_id_hex="33" * 32,
        )
        await client.stream_begin("11" * 32, "22" * 32)

        self.assertEqual(requests[0]["parent_message_id_hex"], "33" * 32)
        self.assertNotIn("parent_message_id_hex", requests[1])

    async def test_stream_finalize_includes_idempotency_key_only_when_supplied(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "stream_finalized",
                    "stream_id_hex": request["stream_id_hex"],
                    "message_ids_hex": ["aa"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        await client.stream_finalize("55" * 32, "33" * 32, "final", "ab" * 32, 1, idempotency_key="key-1")
        await client.stream_finalize("55" * 32, "33" * 32, "final", "ab" * 32, 1, idempotency_key="   ")
        await client.stream_finalize("55" * 32, "33" * 32, "final", "ab" * 32, 1)

        self.assertEqual(requests[0]["idempotency_key"], "key-1")
        self.assertNotIn("idempotency_key", requests[1])
        self.assertNotIn("idempotency_key", requests[2])
        self.assertTrue(all(request["stream_capability"] == "33" * 32 for request in requests))

    async def test_auth_token_is_written_when_configured(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "account_list",
                    "accounts": [],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, auth_token="test-token")

        response = await client.account_list()

        self.assertEqual(response["type"], "account_list")
        self.assertEqual(requests[0]["auth_token"], "test-token")

    async def test_account_lookup_profile_writes_typed_lookup_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "profile_lookup",
                    "account_id_hex": request["account_id_hex"],
                    "status": "profile_found",
                    "retryable": False,
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)
        response = await client.account_lookup_profile("11" * 32)

        self.assertEqual(response["status"], "profile_found")
        self.assertEqual(requests[0]["type"], "account_profile_lookup")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)

    async def test_account_publish_profile_writes_public_profile_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "profile_published",
                    "account_id_hex": request["account_id_hex"],
                    "name": request["name"],
                    "display_name": request["display_name"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.account_publish_profile("11" * 32, "Hermes", "Hermes Agent")

        self.assertEqual(response["type"], "profile_published")
        self.assertEqual(requests[0]["type"], "account_publish_profile")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)
        self.assertEqual(requests[0]["name"], "Hermes")
        self.assertEqual(requests[0]["display_name"], "Hermes Agent")

    async def test_send_agent_operation_event_writes_typed_operation_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "app_event_sent",
                    "message_ids_hex": ["22" * 32],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.send_agent_operation_event(
            "11" * 32,
            "22" * 32,
            event_type="tool_call",
            status="started",
            operation_id="call-1",
            run_id="run-1",
            turn_id="turn-1",
            name="search",
            text="search: glp-1",
            preview="glp-1",
            details={"args": {"query": "glp-1"}},
            sequence=3,
            reply_to_message_id_hex="33" * 32,
        )

        self.assertEqual(response["type"], "app_event_sent")
        self.assertEqual(requests[0]["type"], "send_agent_operation_event")
        self.assertEqual(requests[0]["event_type"], "tool_call")
        self.assertEqual(requests[0]["operation_id"], "call-1")
        self.assertEqual(requests[0]["run_id"], "run-1")
        self.assertEqual(requests[0]["turn_id"], "turn-1")
        self.assertEqual(requests[0]["name"], "search")
        self.assertEqual(requests[0]["preview"], "glp-1")
        self.assertEqual(requests[0]["details"], {"args": {"query": "glp-1"}})
        self.assertEqual(requests[0]["sequence"], 3)
        self.assertEqual(requests[0]["reply_to_message_id_hex"], "33" * 32)

    async def test_inbound_subscription_requires_ack_then_yields_events(self):
        async def handler(reader, writer):
            request = await read_json_line(reader)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "ack",
                },
            )
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
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

    async def test_inbound_subscription_waits_without_request_timeout_after_ack(self):
        ack_sent = asyncio.Event()
        release_event = asyncio.Event()

        async def handler(reader, writer):
            request = await read_json_line(reader)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "ack",
                },
            )
            await writer.drain()
            ack_sent.set()
            await release_event.wait()
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request["id"],
                    "type": "inbound_message",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                    "message_id_hex": "33" * 32,
                    "sender_account_id_hex": "44" * 32,
                    "text": "after idle",
                },
            )
            await writer.drain()
            writer.close()

        await self.start_server(handler)
        request_timeout = 0.1
        client = self.adapter.MarmotAgentControlClient(
            self.socket_path,
            request_timeout=request_timeout,
        )
        events = client.inbound_events(account_id_hex="11" * 32)

        pending_event = asyncio.create_task(anext(events))
        try:
            await asyncio.wait_for(ack_sent.wait(), timeout=1.0)
            await asyncio.sleep(request_timeout * 2)
            self.assertFalse(pending_event.done())

            release_event.set()
            event = await asyncio.wait_for(pending_event, timeout=1.0)

            self.assertEqual(event["type"], "inbound_message")
            self.assertEqual(event["text"], "after idle")
        finally:
            release_event.set()
            if not pending_event.done():
                pending_event.cancel()
                with suppress(asyncio.CancelledError):
                    await pending_event
            await events.aclose()

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

    def test_quic_varint_encoder_matches_rfc9000_boundaries(self):
        cases = {
            0: "00",
            32: "20",
            63: "3f",
            64: "4040",
            16383: "7fff",
            16384: "80004000",
            1073741823: "bfffffff",
            1073741824: "c000000040000000",
            4611686018427387903: "ffffffffffffffff",
        }

        for value, expected_hex in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.adapter._encode_quic_varint(value).hex(), expected_hex)

        with self.assertRaises(ValueError):
            self.adapter._encode_quic_varint(-1)
        with self.assertRaises(ValueError):
            self.adapter._encode_quic_varint(4611686018427387904)

    def test_transcript_matches_rust_status_hash_fixture(self):
        # Mirrors crates/cgka-conformance-simulator/tests/agent_text_stream_vectors.rs:
        # fixed stream_id 0x40..0x5f, fixed start_event_id 0xc0..0xdf,
        # record type 1 text_delta "hello", then record type 3 status "thinking".
        transcript = self.adapter.AgentTextStreamTranscript(
            stream_id_hex=bytes(range(0x40, 0x60)).hex(),
            start_message_id_hex=bytes(range(0xC0, 0xE0)).hex(),
            chunk_bytes=1024,
        )

        self.assertEqual(
            transcript.hash_hex,
            "e4ef961892a7425c1c279f747920ac18d55810732f2aa6b20b330f2666714c78",
        )
        transcript.append_text("hello")
        transcript.append_status("thinking")

        self.assertEqual(transcript.chunk_count, 2)
        self.assertEqual(
            transcript.hash_hex,
            "c0bc23a83a5607f29babfd40464c454306674b82b4653c88fd6f8dbb77e1415c",
        )

    def test_default_stream_chunking_matches_connector_compose_default(self):
        self.assertEqual(self.adapter.DEFAULT_STREAM_CHUNK_BYTES, 1024)

        transcript = self.adapter.AgentTextStreamTranscript(
            stream_id_hex="11" * 32,
            start_message_id_hex="22" * 32,
            chunk_bytes=self.adapter.DEFAULT_STREAM_CHUNK_BYTES,
        )
        transcript.append_text("a" * (self.adapter.DEFAULT_STREAM_CHUNK_BYTES + 1))

        self.assertEqual(transcript.chunk_count, 2)
        self.assertEqual(
            [len(chunk) for chunk in self.adapter.split_text_deltas("a" * 1025, 1024)],
            [1024, 1],
        )

    def test_effective_stream_chunking_clamps_to_policy_frame_len(self):
        self.assertEqual(
            self.adapter.effective_stream_chunk_bytes(
                self.adapter.DEFAULT_STREAM_CHUNK_BYTES,
                4,
            ),
            4,
        )
        self.assertEqual(
            [len(chunk) for chunk in self.adapter.split_text_deltas("abcdefghi", 4)],
            [4, 4, 1],
        )

    def test_append_only_delta_rejects_replacements(self):
        state = self.adapter.AppendOnlyTextState()

        self.assertEqual(state.suffix_for("hello"), "hello")
        self.assertEqual(state.suffix_for("hello world"), " world")
        with self.assertRaises(self.adapter.NonAppendOnlyUpdate):
            state.suffix_for("goodbye")

    def test_profile_name_reply_parser_normalizes_names_and_skip_replies(self):
        parse = self.adapter.parse_profile_name_reply

        self.assertEqual(parse('  "Hermes Agent"  '), ("name", "Hermes Agent", ""))
        self.assertEqual(parse("skip")[0], "skip")
        self.assertEqual(parse(" \n ")[0], "invalid")
        self.assertEqual(parse("x" * 81)[0], "invalid")

    def test_plain_two_word_message_is_not_legacy_tool_progress(self):
        self.assertEqual(self.adapter._tool_events_from_progress_text("hello world"), [])


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

    async def test_auto_selects_sole_local_signing_account(self):
        class FakeClient:
            async def account_list(self):
                return {
                    "type": "account_list",
                    "accounts": [
                        {"account_id_hex": "aa" * 32, "label": "mirror", "local_signing": False},
                        {"account_id_hex": "bb" * 32, "label": "agent", "local_signing": True},
                    ],
                }

        adapter = self.adapter_module.MarmotPlatformAdapter(self.config_cls(extra={}), client=FakeClient())

        account_id = await adapter._ensure_account_id()

        self.assertEqual(account_id, "bb" * 32)
        self.assertEqual(adapter.account_id_hex, "bb" * 32)

    async def test_auto_select_rejects_non_signing_only_account(self):
        class FakeClient:
            async def account_list(self):
                return {
                    "type": "account_list",
                    "accounts": [
                        {"account_id_hex": "aa" * 32, "label": "mirror", "local_signing": False},
                    ],
                }

        adapter = self.adapter_module.MarmotPlatformAdapter(self.config_cls(extra={}), client=FakeClient())

        with self.assertRaises(self.adapter_module.AgentControlError) as raised:
            await adapter._ensure_account_id()

        self.assertEqual(raised.exception.code, "no_accounts")

    async def test_auto_select_rejects_multiple_signing_accounts(self):
        class FakeClient:
            async def account_list(self):
                return {
                    "type": "account_list",
                    "accounts": [
                        {"account_id_hex": "aa" * 32, "label": "agent-1", "local_signing": True},
                        {"account_id_hex": "bb" * 32, "label": "agent-2", "local_signing": True},
                    ],
                }

        adapter = self.adapter_module.MarmotPlatformAdapter(self.config_cls(extra={}), client=FakeClient())

        with self.assertRaises(self.adapter_module.AgentControlError) as raised:
            await adapter._ensure_account_id()

        self.assertEqual(raised.exception.code, "ambiguous_account")

    async def test_adapter_reads_auth_token_file_for_control_client(self):
        with tempfile.TemporaryDirectory() as tempdir:
            token_file = Path(tempdir) / "control.token"
            token_file.write_text("file-token\n", encoding="utf-8")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "socket_path": str(Path(tempdir) / "wn-agent.sock"),
                        "auth_token_file": str(token_file),
                    }
                )
            )

        self.assertEqual(adapter.client.auth_token, "file-token")

    async def test_send_maps_hermes_chat_to_marmot_send_final(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
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

    async def test_tool_progress_send_maps_to_agent_operation_event(self):
        class FakeClient:
            def __init__(self):
                self.tool_events = []
                self.final_sends = []

            async def send_agent_operation_event(self, account_id_hex, group_id_hex, **kwargs):
                self.tool_events.append((account_id_hex, group_id_hex, kwargs))
                return {
                    "type": "app_event_sent",
                    "message_ids_hex": ["44" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        result = await adapter.send(
            chat_id="22" * 32,
            content='* search: "glp-1"',
            reply_to="33" * 32,
        )

        self.assertTrue(result.success)
        self.assertTrue(result.message_id.startswith("marmot-tool-progress:"))
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.tool_events), 1)
        account_id, group_id, kwargs = fake_client.tool_events[0]
        self.assertEqual(account_id, "11" * 32)
        self.assertEqual(group_id, "22" * 32)
        self.assertEqual(kwargs["event_type"], "tool_call")
        self.assertEqual(kwargs["status"], "started")
        self.assertEqual(kwargs["name"], "search")
        self.assertEqual(kwargs["preview"], "glp-1")
        self.assertEqual(kwargs["reply_to_message_id_hex"], "33" * 32)

    async def test_tool_progress_retry_resends_failed_event(self):
        class FakeClient:
            def __init__(self):
                self.tool_events = []
                self.final_sends = []
                self.fail_next = True

            async def send_agent_operation_event(self, account_id_hex, group_id_hex, **kwargs):
                self.tool_events.append((account_id_hex, group_id_hex, kwargs))
                if self.fail_next:
                    self.fail_next = False
                    raise RuntimeError("temporary send failure")
                return {
                    "type": "app_event_sent",
                    "message_ids_hex": ["44" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        first = await adapter.send(
            chat_id="22" * 32,
            content='* search: "glp-1"',
            reply_to="33" * 32,
        )
        self.assertFalse(first.success)
        self.assertTrue(first.message_id.startswith("marmot-tool-progress:"))

        retry = await adapter.edit_message(
            chat_id="22" * 32,
            message_id=first.message_id,
            content='* search: "glp-1"\u2589',
        )

        self.assertTrue(retry.success)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.tool_events), 2)
        self.assertEqual(fake_client.tool_events[0][0:2], fake_client.tool_events[1][0:2])
        self.assertEqual(fake_client.tool_events[0][2], fake_client.tool_events[1][2])
        self.assertEqual(fake_client.tool_events[1][2]["reply_to_message_id_hex"], "33" * 32)

    async def test_disconnect_clears_tool_progress_dedupe_cache(self):
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=object(),
        )
        adapter._tool_progress_events["marmot-tool-progress:test"] = {"event"}
        adapter._tool_progress_replies["marmot-tool-progress:test"] = "33" * 32

        await adapter.disconnect()

        self.assertEqual(adapter._tool_progress_events, {})
        self.assertEqual(adapter._tool_progress_replies, {})

    async def test_connect_accepts_gateway_is_reconnect_keyword(self):
        # hermes-agent's gateway connects adapters via connect(is_reconnect=...)
        # on cold boot and reconnect alike, so a signature without the
        # keyword-only argument raises TypeError before the platform ever
        # comes up (#836).
        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                await asyncio.Event().wait()
                yield {}  # unreachable: marks this as an async generator

        for is_reconnect in (False, True):
            with self.subTest(is_reconnect=is_reconnect):
                adapter = self.adapter_module.MarmotPlatformAdapter(
                    self.config_cls(extra={"account_id_hex": "11" * 32}),
                    client=FakeClient(),
                )
                try:
                    self.assertTrue(await adapter.connect(is_reconnect=is_reconnect))
                    self.assertTrue(adapter._running)
                    self.assertIsNotNone(adapter._listener_task)
                finally:
                    await adapter.disconnect()
                self.assertIsNone(adapter._listener_task)

    async def test_inbound_event_is_forwarded_to_hermes_message_event(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "ping",
                "mentions_self": True,
            }
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        await adapter._consume_inbound_once(drain=True)

        self.assertEqual(len(adapter.events), 1)
        event = adapter.events[0]
        self.assertEqual(event.text, "ping")
        self.assertEqual(event.message_id, "33" * 32)
        self.assertEqual(event.source.chat_id, "22" * 32)
        self.assertEqual(event.source.chat_type, "group")
        self.assertEqual(event.source.user_id, "44" * 32)

    async def test_resync_required_event_raises_to_force_reconnect(self):
        # Regression for mdk#210: a resync_required event (emitted when the connector
        # dropped inbound messages on broadcast lag and could not auto-replay them) must NOT be
        # silently ignored. It must raise so the consume loop reconnects, re-running the
        # connector's catch-up and storage-backed replay to recover the missed messages.
        events = [
            {
                "type": "resync_required",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "dropped_events": 1500,
            }
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        with self.assertRaises(self.adapter_module._ResyncRequired):
            await adapter._consume_inbound_once()
        # The resync signal is not delivered to the agent as a message.
        self.assertEqual(adapter.events, [])

    async def test_consume_loop_reconnects_after_resync_then_delivers(self):
        # The consume loop must survive a resync_required (reconnect) and then deliver the
        # message recovered on the fresh subscription, rather than crashing or dropping it.
        attempts = {"n": 0}

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                # Yield control so the event loop can run the test's poll/cancel between
                # reconnect attempts (the consume loop reconnects in a tight cycle otherwise).
                await asyncio.sleep(0)
                if attempts["n"] == 1:
                    yield {
                        "type": "resync_required",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": "22" * 32,
                        "dropped_events": 3,
                    }
                elif attempts["n"] == 2:
                    yield wire_event({
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": "22" * 32,
                        "message_id_hex": "33" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "recovered after resync",
                        "mentions_self": True,
                    })
                else:
                    # No further events; idle so the loop parks instead of busy-spinning.
                    await asyncio.sleep(3600)
                    return

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        # Drive the loop just long enough to reconnect once and deliver the recovered message.
        loop_task = asyncio.ensure_future(adapter._consume_inbound_loop())
        try:
            for _ in range(300):
                if adapter.events:
                    break
                await asyncio.sleep(0.01)
        finally:
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        self.assertGreaterEqual(attempts["n"], 2, "loop should reconnect after resync")
        self.assertEqual(len(adapter.events), 1)
        self.assertEqual(adapter.events[0].text, "recovered after resync")

    async def test_slow_group_turn_does_not_block_dispatch_for_other_groups(self):
        # mdk#513: inbound was dispatched serially (async for -> await handle_message),
        # so a slow/hung turn in one group blocked dispatch for every group. With per-group
        # serialization, a stuck turn in group A must NOT prevent group B's turn from running.
        group_a = "aa" * 32
        group_b = "bb" * 32

        def make_event(group_id_hex, message_id_hex, text):
            return {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group_id_hex,
                "message_id_hex": message_id_hex,
                "sender_account_id_hex": "44" * 32,
                "text": text,
                "mentions_self": True,
            }

        events = [
            make_event(group_a, "01" * 32, "slow group A"),
            make_event(group_b, "02" * 32, "fast group B"),
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)
                # Keep the subscription open after yielding so the consume loop parks on the
                # next event instead of draining the queue (which would serialize the turns).
                await asyncio.sleep(3600)

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        release_a = asyncio.Event()
        completed = []

        async def handle_message(event):
            chat_id = event.source.chat_id
            if chat_id == group_a:
                # Group A's turn is "slow/hung": it blocks until the test releases it.
                await release_a.wait()
            completed.append(chat_id)

        adapter.handle_message = handle_message

        loop_task = asyncio.ensure_future(adapter._consume_inbound_once())
        try:
            # Group B should complete while group A is still blocked: no head-of-line blocking.
            for _ in range(200):
                if group_b in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(
                group_b,
                completed,
                "group B turn must dispatch while group A's turn is still in flight",
            )
            self.assertNotIn(
                group_a,
                completed,
                "group A turn must still be blocked (it was not released yet)",
            )

            # Releasing group A lets its turn finish too — nothing was dropped.
            release_a.set()
            for _ in range(200):
                if group_a in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(group_a, completed, "group A turn must complete once released")
        finally:
            loop_task.cancel()
            with suppress(asyncio.CancelledError):
                await loop_task
            await adapter._inbound_queue.cancel_all()

    async def test_same_group_turns_dispatch_in_fifo_order(self):
        # Per-group ordering must be preserved: two messages for the SAME group run strictly
        # in arrival order, with the second turn waiting for the first to finish.
        group = "cc" * 32

        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group,
                "message_id_hex": "01" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "first",
                "mentions_self": True,
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group,
                "message_id_hex": "02" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "second",
                "mentions_self": True,
            },
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        order = []

        async def handle_message(event):
            text = event.text
            order.append(f"start:{text}")
            if text == "first":
                # Yield control after the first turn starts so that, if ordering were broken,
                # the second turn would have a chance to interleave before "first" finishes.
                await asyncio.sleep(0.05)
            order.append(f"end:{text}")

        adapter.handle_message = handle_message

        await adapter._consume_inbound_once(drain=True)

        # Strict FIFO: first fully completes before second starts.
        self.assertEqual(
            order,
            ["start:first", "end:first", "start:second", "end:second"],
        )

    async def test_first_inbound_message_prompts_for_public_profile_name(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hello",
                "mentions_self": True,
            }
        ]

        class FakeClient:
            def __init__(self):
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)

            async def account_lookup_profile(self, account_id_hex):
                return {"type": "profile_lookup", "status": "profile_not_found", "retryable": False}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(Path(tempdir) / "profile-state.json"),
                    }
                ),
                client=fake_client,
            )

            await adapter._consume_inbound_once(drain=True)

        self.assertEqual(adapter.events, [])
        self.assertEqual(len(fake_client.final_sends), 1)
        account_id, group_id, text, reply_to = fake_client.final_sends[0]
        self.assertEqual(account_id, "11" * 32)
        self.assertEqual(group_id, "22" * 32)
        self.assertIn("public Nostr profile", text)
        self.assertEqual(reply_to, "33" * 32)

    async def test_existing_public_profile_suppresses_prompt_and_persists_state(self):
        account_id = "11" * 32
        group_id = "22" * 32

        class FakeClient:
            def __init__(self):
                self.lookup_calls = 0
                self.final_sends = []

            async def account_lookup_profile(self, requested_account_id):
                self.lookup_calls += 1
                self.asserted_account = requested_account_id
                return {"type": "profile_lookup", "status": "profile_found", "retryable": False}

            async def send_final(self, *args, **kwargs):
                self.final_sends.append((args, kwargs))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            state_path = Path(tempdir) / "profile-state.json"
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account_id,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                    }
                ),
                client=fake_client,
            )
            event = {
                "type": "inbound_message",
                "account_id_hex": account_id,
                "group_id_hex": group_id,
                "message_id_hex": "33" * 32,
                "text": "hello",
            }

            self.assertFalse(await adapter._maybe_handle_profile_name_onboarding(event))
            self.assertFalse(await adapter._maybe_handle_profile_name_onboarding(event))
            self.assertEqual(fake_client.lookup_calls, 1)
            self.assertEqual(fake_client.final_sends, [])
            self.assertEqual((await adapter.profile_name_onboarding.get(account_id)).get("status"), "profile_exists")

            reopened = self.adapter_module.ProfileNameOnboardingStore(state_path)
            self.assertEqual((await reopened.get(account_id)).get("status"), "profile_exists")

    async def test_indeterminate_profile_lookup_backs_off_without_prompting_then_retries(self):
        account_id = "11" * 32
        group_id = "22" * 32
        now = [100.0]

        class FakeClient:
            def __init__(self):
                self.lookup_calls = 0
                self.final_sends = []

            async def account_lookup_profile(self, requested_account_id):
                self.lookup_calls += 1
                status = "indeterminate" if self.lookup_calls == 1 else "profile_not_found"
                return {"type": "profile_lookup", "status": status, "retryable": status == "indeterminate"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account_id,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(Path(tempdir) / "profile-state.json"),
                    }
                ),
                client=fake_client,
            )
            adapter._profile_lookup_gate = self.adapter_module.ProfileLookupGate(
                now=lambda: now[0], backoff_seconds=(1.0, 5.0)
            )
            event = {
                "type": "inbound_message",
                "account_id_hex": account_id,
                "group_id_hex": group_id,
                "message_id_hex": "33" * 32,
                "text": "hello",
            }

            self.assertFalse(await adapter._maybe_handle_profile_name_onboarding(event))
            self.assertFalse(await adapter._maybe_handle_profile_name_onboarding(event))
            self.assertEqual(fake_client.lookup_calls, 1)
            self.assertEqual(fake_client.final_sends, [])
            self.assertEqual(await adapter.profile_name_onboarding.get(account_id), {})

            now[0] += 1.0
            self.assertTrue(await adapter._maybe_handle_profile_name_onboarding(event))
            self.assertEqual(fake_client.lookup_calls, 2)
            self.assertEqual(len(fake_client.final_sends), 1)

    async def test_profile_name_reply_publishes_profile_and_acknowledges(self):
        account_id = "11" * 32
        group_id = "22" * 32
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": account_id,
                "group_id_hex": group_id,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "  Hermes Agent  ",
                "mentions_self": True,
            }
        ]

        class FakeClient:
            def __init__(self):
                self.published_profiles = []
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield wire_event(event)

            async def account_publish_profile(self, account_id_hex, name, display_name=None):
                self.published_profiles.append((account_id_hex, name, display_name))
                return {
                    "type": "profile_published",
                    "account_id_hex": account_id_hex,
                    "name": name,
                    "display_name": display_name,
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            state_path = Path(tempdir) / "profile-state.json"
            store = self.adapter_module.ProfileNameOnboardingStore(state_path)
            await store.mark_prompted(account_id, group_id)
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account_id,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                    }
                ),
                client=fake_client,
            )

            await adapter._consume_inbound_once(drain=True)

        self.assertEqual(adapter.events, [])
        self.assertEqual(fake_client.published_profiles, [(account_id, "Hermes Agent", "Hermes Agent")])
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertIn('published this agent', fake_client.final_sends[0][2])
        self.assertEqual(fake_client.final_sends[0][3], "33" * 32)

    async def test_hung_group_does_not_block_reconnect_for_other_groups(self):
        # mdk#513 (adversarial follow-up): the inline-dispatch fix kept the happy path
        # unblocked, but draining the per-group queue on stream end re-introduced head-of-line
        # blocking on the RECONNECT path. The queue is long-lived (owned by the adapter) and must
        # survive resync: a hung turn in group A must not hold the resync hostage, or group B —
        # delivered only on the fresh post-resync subscription — never runs.
        group_a = "aa" * 32
        group_b = "bb" * 32
        attempts = {"n": 0}

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                await asyncio.sleep(0)
                if attempts["n"] == 1:
                    # First subscription: a slow/hung group-A turn, then a resync forces reconnect.
                    yield wire_event({
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_a,
                        "message_id_hex": "01" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "slow group A",
                        "mentions_self": True,
                    })
                    yield {
                        "type": "resync_required",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_a,
                        "dropped_events": 3,
                    }
                elif attempts["n"] == 2:
                    # Fresh subscription after resync delivers group B's message.
                    yield wire_event({
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_b,
                        "message_id_hex": "02" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "fast group B",
                        "mentions_self": True,
                    })
                else:
                    await asyncio.sleep(3600)
                    return

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        release_a = asyncio.Event()
        completed = []

        async def handle_message(event):
            chat_id = event.source.chat_id
            if chat_id == group_a:
                await release_a.wait()  # group A's turn is hung until the test releases it
            completed.append(chat_id)

        adapter.handle_message = handle_message

        loop_task = asyncio.ensure_future(adapter._consume_inbound_loop())
        try:
            # Group B must complete even though group A's turn is still hung AND a resync had to
            # reconnect the subscription in between. If the loop joined the queue on stream end,
            # the resync (and therefore group B) would be stuck behind hung group A forever.
            for _ in range(300):
                if group_b in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(
                group_b,
                completed,
                "group B must dispatch after resync-reconnect even while group A is hung",
            )
            self.assertNotIn(
                group_a,
                completed,
                "group A turn must still be blocked (it was not released yet)",
            )
            self.assertGreaterEqual(attempts["n"], 2, "loop should reconnect after resync")

            # Releasing group A lets its turn finish too — nothing was dropped.
            release_a.set()
            for _ in range(300):
                if group_a in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(group_a, completed, "group A turn must complete once released")
        finally:
            loop_task.cancel()
            with suppress(asyncio.CancelledError):
                await loop_task
            await adapter._inbound_queue.cancel_all()

    async def test_concurrent_first_messages_prompt_once_and_consume_one(self):
        # mdk#513 (adversarial follow-up): under the new per-group concurrency, two first
        # messages for the SAME account in DIFFERENT groups could both read empty onboarding state
        # before either wrote "prompted", so both sent a prompt and both original user messages
        # were swallowed. The atomic try_claim_prompt() must let exactly one group win the prompt;
        # the other group's message must fall through to a normal agent turn (not be consumed).
        account = "11" * 32
        group_a = "aa" * 32
        group_b = "bb" * 32

        def make_event(group_id_hex, message_id_hex, text):
            return {
                "type": "inbound_message",
                "account_id_hex": account,
                "group_id_hex": group_id_hex,
                "message_id_hex": message_id_hex,
                "sender_account_id_hex": "44" * 32,
                "text": text,
                "mentions_self": True,
            }

        class FakeClient:
            def __init__(self):
                self.final_sends = []
                self.lookup_calls = 0
                self._lookup_started = asyncio.Event()
                self._release_lookup = asyncio.Event()
                self._prompt_started = asyncio.Event()
                self._release = asyncio.Event()

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                if False:  # pragma: no cover - generator shape only
                    yield {}

            async def account_lookup_profile(self, account_id_hex):
                self.lookup_calls += 1
                self._lookup_started.set()
                await self._release_lookup.wait()
                return {"type": "profile_lookup", "status": "profile_not_found", "retryable": False}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                # Make the first prompt-send slow so both groups are in flight concurrently:
                # the race window is widest when one send is suspended mid-flight.
                first = not self._prompt_started.is_set()
                if first:
                    self._prompt_started.set()
                    await self._release.wait()
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(Path(tempdir) / "profile-state.json"),
                    }
                ),
                client=fake_client,
            )

            turns = []

            async def handle_message(event):
                turns.append((event.source.chat_id, event.text))

            adapter.handle_message = handle_message

            # Dispatch both groups' first messages concurrently through the real per-group queue.
            adapter._inbound_queue.enqueue(
                group_a, lambda: adapter._dispatch_inbound_message(make_event(group_a, "01" * 32, "hi from A"))
            )
            adapter._inbound_queue.enqueue(
                group_b, lambda: adapter._dispatch_inbound_message(make_event(group_b, "02" * 32, "hi from B"))
            )

            # Let both groups share the same in-flight lookup, then release the slow prompt send.
            for _ in range(200):
                if fake_client._lookup_started.is_set():
                    break
                await asyncio.sleep(0.005)
            fake_client._release_lookup.set()
            for _ in range(200):
                if fake_client._prompt_started.is_set():
                    break
                await asyncio.sleep(0.005)
            fake_client._release.set()
            await adapter._inbound_queue.join()

        self.assertEqual(fake_client.lookup_calls, 1, "concurrent groups must share one profile lookup")
        # Exactly one prompt was sent (the claim winner); the loser did NOT also prompt.
        self.assertEqual(
            len(fake_client.final_sends), 1, f"expected exactly one prompt, got {fake_client.final_sends}"
        )
        # Exactly one original message was consumed as a prompt trigger; the other fell through
        # to a normal agent turn instead of being swallowed.
        self.assertEqual(len(turns), 1, f"expected exactly one normal turn, got {turns}")
        # The group that was prompted is NOT the group that ran a normal turn.
        prompted_group = fake_client.final_sends[0][1]
        turn_group = turns[0][0]
        self.assertNotEqual(prompted_group, turn_group)
        self.assertEqual({prompted_group, turn_group}, {group_a, group_b})

    async def test_profile_prompt_send_failure_releases_claim_for_retry(self):
        # If the claim winner cannot deliver the prompt, it must release the slot (clear) so a
        # later inbound message retries — otherwise the account is stuck "prompted" with no
        # prompt ever delivered and every message is silently swallowed.
        account = "11" * 32
        group = "22" * 32

        class FakeClient:
            def __init__(self):
                self.calls = 0
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                if False:  # pragma: no cover - generator shape only
                    yield {}

            async def account_lookup_profile(self, account_id_hex):
                return {"type": "profile_lookup", "status": "profile_not_found", "retryable": False}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.calls += 1
                if self.calls == 1:
                    # First prompt send fails: _send_final_direct maps a raised exception to
                    # SendResult(success=False), which must trigger the claim release.
                    raise RuntimeError("transient send failure")
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            state_path = Path(tempdir) / "profile-state.json"
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                    }
                ),
                client=fake_client,
            )
            store = adapter.profile_name_onboarding

            event = {
                "type": "inbound_message",
                "account_id_hex": account,
                "group_id_hex": group,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hi",
            }

            # First attempt: claim succeeds, send fails, slot must be released (not "prompted").
            consumed_first = await adapter._maybe_handle_profile_name_onboarding(event)
            self.assertFalse(consumed_first, "failed prompt must not consume the message")
            self.assertEqual(await store.get(account), {}, "claim must be released after send failure")

            # Second attempt: a later message retries and now succeeds.
            consumed_second = await adapter._maybe_handle_profile_name_onboarding(event)
            self.assertTrue(consumed_second, "retry should prompt and consume the message")
            self.assertEqual(len(fake_client.final_sends), 1)
            self.assertEqual((await store.get(account)).get("status"), "prompted")

    async def test_inbound_turn_parent_reaches_draft_stream_without_state_leak(self):
        class FakeClient:
            def __init__(self):
                self.stream_begin_parents = []

            async def stream_begin(
                self,
                account_id_hex,
                group_id_hex,
                *,
                stream_id_hex=None,
                parent_message_id_hex=None,
                quic_candidates=(),
                request_id=None,
            ):
                self.stream_begin_parents.append(parent_message_id_hex)
                index = len(self.stream_begin_parents)
                return {
                    "type": "stream_begun",
                    "stream_id_hex": f"{index:02x}" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": f"{index + 16:02x}" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                    "group_activation": "always",
                }
            ),
            client=fake_client,
        )
        next_draft_id = 0

        async def message_handler(event):
            nonlocal next_draft_id
            next_draft_id += 1
            result = await adapter.send_draft(
                event.source.chat_id,
                next_draft_id,
                "hello",
            )
            self.assertTrue(result.success)

        adapter._message_handler = message_handler

        def turn_event(message_id_hex):
            source = adapter.build_source(
                chat_id="22" * 32,
                chat_type="group",
                user_id="44" * 32,
                message_id=message_id_hex,
            )
            return self.adapter_module.MessageEvent(
                text="hello",
                source=source,
                message_id=message_id_hex,
            )

        for index, parent_message_id_hex in enumerate(("33" * 32, "34" * 32, None)):
            session_key = f"session-{index}"
            started = adapter._start_session_processing(
                turn_event(parent_message_id_hex),
                session_key,
            )
            self.assertTrue(started)
            await adapter._session_tasks[session_key]

        self.assertEqual(
            fake_client.stream_begin_parents,
            ["33" * 32, "34" * 32, None],
        )
        self.assertIsNone(self.adapter_module._TURN_PARENT_MESSAGE_ID_HEX.get())

    async def test_progressive_edit_stream_finalizes_then_sends_durable_message(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(
                self,
                account_id_hex,
                group_id_hex,
                *,
                stream_id_hex=None,
                parent_message_id_hex=None,
                quic_candidates=(),
                request_id=None,
            ):
                self.stream_begin_args = (
                    account_id_hex,
                    group_id_hex,
                    parent_message_id_hex,
                    tuple(quic_candidates),
                )
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
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

        first = await adapter.send("22" * 32, "hel\u2589", reply_to="33" * 32)
        self.assertTrue(first.success)
        self.assertEqual(first.message_id, "marmot-stream:" + "55" * 32)
        self.assertEqual(
            fake_client.stream_begin_args,
            ("11" * 32, "22" * 32, "33" * 32, ("quic://127.0.0.1:4433",)),
        )

        edited = await adapter.edit_message("22" * 32, first.message_id, "hello\u2589")
        self.assertTrue(edited.success)

        final = await adapter.edit_message("22" * 32, first.message_id, "hello", finalize=True)

        self.assertTrue(final.success)
        self.assertEqual(final.message_id, "77" * 32)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "hel"), ("55" * 32, "lo")],
        )
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.stream_finalizes[0][1], "hello")
        self.assertEqual(fake_client.stream_finalizes[0][3], 2)
        self.assertEqual(fake_client.final_sends, [])

    async def test_stream_transcript_chunks_at_policy_frame_len_from_begin_response(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                    "policy_max_plaintext_frame_len": 4,
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        preview = await adapter.send("22" * 32, "abcdefghi\u2589")
        final = await adapter.edit_message("22" * 32, preview.message_id, "abcdefghi", finalize=True)

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.stream_appends, [("55" * 32, "abcdefghi")])
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.stream_finalizes[0][1], "abcdefghi")
        self.assertEqual(fake_client.stream_finalizes[0][3], 3)
        self.assertEqual(fake_client.final_sends, [])

    async def test_draft_stream_skips_empty_visible_frames(self):
        class FakeClient:
            def __init__(self):
                self.stream_begins = []
                self.stream_appends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                self.stream_begins.append((account_id_hex, group_id_hex, tuple(quic_candidates)))
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

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

        result = await adapter.send_draft("22" * 32, 1, "\u2589")

        self.assertTrue(result.success)
        self.assertEqual(fake_client.stream_begins, [])
        self.assertEqual(fake_client.stream_appends, [])

    async def test_draft_stream_clear_cancels_existing_preview(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

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

        first = await adapter.send_draft("22" * 32, 1, "Let me search")
        cleared = await adapter.send_draft("22" * 32, 1, "\u2589")

        self.assertTrue(first.success)
        self.assertTrue(cleared.success)
        self.assertEqual(fake_client.stream_appends, [("55" * 32, "Let me search")])
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "draft cleared")])
        self.assertEqual(adapter._draft_streams, {})

    async def test_draft_stream_rotation_cancels_previous_preview(self):
        class FakeClient:
            def __init__(self):
                self.next_stream = 0
                self.stream_appends = []
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

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

        first = await adapter.send_draft("22" * 32, 1, "Let me search")
        second = await adapter.send_draft("22" * 32, 2, "Based on")

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "Let me search"), ("56" * 32, "Based on")],
        )
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "superseded by newer draft")])

    async def test_new_preview_cancels_previous_chat_stream(self):
        class FakeClient:
            def __init__(self):
                self.next_stream = 0
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

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
        second = await adapter.send("22" * 32, "hello\u2589")

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(
            fake_client.stream_cancels,
            [("55" * 32, "superseded by newer preview")],
        )
        self.assertEqual(second.message_id, "marmot-stream:" + "56" * 32)

    async def test_send_final_extension_finalizes_stream(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        preview = await adapter.send("22" * 32, "Based on my research\u2589")
        final = await adapter.send("22" * 32, "Based on my research, here's the answer")

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(final.message_id, "77" * 32)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(
            fake_client.stream_finalizes[0][1],
            "Based on my research, here's the answer",
        )

    async def test_markdown_balancers_after_cursor_stay_a_preview(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(
                self,
                account_id_hex,
                group_id_hex,
                *,
                stream_id_hex=None,
                parent_message_id_hex=None,
                quic_candidates=(),
                request_id=None,
            ):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(
                self,
                stream_id_hex,
                stream_capability,
                final_text,
                transcript_hash_hex,
                chunk_count,
                idempotency_key=None,
            ):
                self.stream_finalizes.append((stream_id_hex, final_text))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(
                self,
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex=None,
                idempotency_key=None,
            ):
                self.final_sends.append((account_id_hex, group_id_hex, text))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        # Hermes balances an open inline-code span after adding its cursor. The
        # trailing backtick is display-only and must not hide the preview marker.
        preview = await adapter.send("22" * 32, "Result: `partial \u2589`")
        final = await adapter.send("22" * 32, "Result: `partial value`")

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(fake_client.stream_appends[0][1], "Result: `partial ")
        self.assertEqual(
            fake_client.stream_finalizes,
            [("55" * 32, "Result: `partial value`")],
        )

        # Fenced blocks are balanced with a newline plus three backticks.
        append_offset = len(fake_client.stream_appends)
        finalize_offset = len(fake_client.stream_finalizes)
        fenced_preview = await adapter.send("22" * 32, "```text\npartial \u2589\n```")
        fenced_final = await adapter.send("22" * 32, "```text\npartial value\n```")

        self.assertTrue(fenced_preview.success)
        self.assertTrue(fenced_final.success)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(fake_client.stream_appends[append_offset][1], "```text\npartial ")
        self.assertEqual(len(fake_client.stream_finalizes), finalize_offset + 1)
        self.assertEqual(
            fake_client.stream_finalizes[finalize_offset],
            ("55" * 32, "```text\npartial value\n```"),
        )

        both_balancers = "`outside\n```text\npartial \u2589\n````"
        self.assertTrue(adapter._looks_like_stream_preview(both_balancers))
        self.assertEqual(
            adapter._strip_streaming_cursor(both_balancers),
            "`outside\n```text\npartial ",
        )

        # Whitespace after the cursor is part of the visible snapshot. Preserve
        # its exact bytes so later append-only comparisons see the same text.
        for trailing_whitespace in (" ", "\t", "\r\n", " \t\r\n"):
            with self.subTest(trailing_whitespace=repr(trailing_whitespace)):
                preview_with_whitespace = "partial \u2589`" + trailing_whitespace
                self.assertEqual(
                    adapter._split_stream_preview(preview_with_whitespace),
                    ("partial " + trailing_whitespace, True),
                )

    async def test_whitespace_mismatched_final_replaces_preview_without_duplication(self):
        class FakeClient:
            def __init__(self):
                self.stream_finalizes = []
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                self.stream_finalizes.append((stream_id_hex, final_text))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        # The preview snapshot keeps a trailing space before the cursor; the
        # final send is the rstripped text. The mismatch must not duplicate or
        # concatenate text in the durable final.
        segment = "\n\nLet me use the web search tool to find current titanium prices:"
        preview = await adapter.send("22" * 32, segment + " \u2589")
        final = await adapter.send("22" * 32, segment)

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(
            fake_client.stream_cancels,
            [("55" * 32, "final text was not append-only")],
        )
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertEqual(fake_client.final_sends[0][2], segment)

    async def test_final_send_cancels_non_append_only_draft_preview(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {"type": "stream_finalized", "stream_id_hex": stream_id_hex}

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
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

        draft = await adapter.send_draft("22" * 32, 1, "Let me search")
        final = await adapter.send("22" * 32, "Based on my search")

        self.assertTrue(draft.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.stream_appends, [("55" * 32, "Let me search")])
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "final text was not append-only")])
        self.assertEqual(
            fake_client.final_sends,
            [("11" * 32, "22" * 32, "Based on my search", None)],
        )


class _DeliveryRoutingFakeClient:
    def __init__(self):
        self.activities = []
        self.tool_events = []
        self.final_sends = []
        self.stream_begins = []
        self.stream_appends = []
        self.stream_finalizes = []
        self.stream_cancels = []
        self.activity_attempts = 0
        self.fail_next_activity = False
        self.activity_response = {
            "type": "app_event_sent",
            "message_ids_hex": ["aa" * 32],
        }

    async def send_agent_activity(self, account_id_hex, group_id_hex, **kwargs):
        self.activity_attempts += 1
        if self.fail_next_activity:
            self.fail_next_activity = False
            raise OSError("temporary activity failure")
        self.activities.append((account_id_hex, group_id_hex, kwargs))
        return self.activity_response

    async def send_agent_operation_event(self, account_id_hex, group_id_hex, **kwargs):
        self.tool_events.append((account_id_hex, group_id_hex, kwargs))
        return {"type": "app_event_sent", "message_ids_hex": ["bb" * 32]}

    async def send_final(
        self,
        account_id_hex,
        group_id_hex,
        text,
        reply_to_message_id_hex=None,
        idempotency_key=None,
    ):
        self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
        return {"type": "final_sent", "message_ids_hex": ["cc" * 32]}

    async def stream_begin(
        self,
        account_id_hex,
        group_id_hex,
        *,
        stream_id_hex=None,
        quic_candidates=(),
        request_id=None,
        parent_message_id_hex=None,
    ):
        self.stream_begins.append((account_id_hex, group_id_hex, parent_message_id_hex))
        return {
            "type": "stream_begun",
            "stream_id_hex": "55" * 32,
            "stream_capability": "33" * 32,
            "start_message_id_hex": "66" * 32,
            "quic_candidates": list(quic_candidates),
        }

    async def stream_append(self, stream_id_hex, stream_capability, append_text):
        self.stream_appends.append((stream_id_hex, append_text))
        return {"type": "ack"}

    async def stream_finalize(
        self,
        stream_id_hex,
        stream_capability,
        final_text,
        transcript_hash_hex,
        chunk_count,
        idempotency_key=None,
    ):
        self.stream_finalizes.append((stream_id_hex, final_text))
        return {
            "type": "stream_finalized",
            "stream_id_hex": stream_id_hex,
            "message_ids_hex": ["77" * 32],
        }

    async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
        self.stream_cancels.append((stream_id_hex, reason))
        return {"type": "ack"}


class DeliveryMetadataRoutingTests(unittest.IsolatedAsyncioTestCase):
    NON_FINAL_COMMENTARY = {"is_turn_final": False, "delivery_class": "commentary"}

    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    def _adapter(self, fake_client, *, quic_candidates=None):
        extra = {"account_id_hex": "11" * 32}
        if quic_candidates is not None:
            extra["quic_candidates"] = quic_candidates
        return self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra=extra),
            client=fake_client,
        )

    async def test_direct_commentary_metadata_variants_map_to_activity(self):
        cases = [
            ("is_turn_final canonical", {"is_turn_final": False}),
            ("turn_final alias", {"turn_final": False}),
            ("delivery_context container", {"delivery_context": {"is_turn_final": False}}),
            ("delivery container", {"delivery": {"delivery_class": "commentary"}}),
        ]
        for label, metadata in cases:
            with self.subTest(label=label):
                fake_client = _DeliveryRoutingFakeClient()
                adapter = self._adapter(fake_client)
                result = await adapter.send(
                    chat_id="22" * 32,
                    content="I'll check that now.",
                    reply_to="33" * 32,
                    metadata=metadata,
                )
                self.assertTrue(result.success, label)
                self.assertEqual(result.message_id, "aa" * 32, label)
                self.assertEqual(len(fake_client.activities), 1, label)
                self.assertEqual(fake_client.final_sends, [], label)
                self.assertEqual(fake_client.activities[0][2]["status"], "commentary", label)
                self.assertEqual(fake_client.activities[0][2]["reply_to_message_id_hex"], "33" * 32, label)

    async def test_explicit_non_final_overrides_every_delivery_class(self):
        delivery_classes = ("final", "approval", "commentary", "operation", "notice", "mystery")
        for finality_key in ("is_turn_final", "turn_final"):
            for delivery_class in delivery_classes:
                with self.subTest(finality_key=finality_key, delivery_class=delivery_class):
                    fake_client = _DeliveryRoutingFakeClient()
                    adapter = self._adapter(fake_client)
                    result = await adapter.send(
                        chat_id="22" * 32,
                        content="Still working.",
                        metadata={"delivery_class": delivery_class, finality_key: False},
                    )
                    self.assertTrue(result.success)
                    self.assertEqual(len(fake_client.activities), 1)
                    self.assertEqual(fake_client.final_sends, [])
                    self.assertEqual(fake_client.activities[0][2]["status"], "commentary")

    async def test_explicit_turn_final_overrides_every_delivery_class(self):
        delivery_classes = ("final", "approval", "commentary", "operation", "notice", "mystery")
        for finality_key in ("is_turn_final", "turn_final"):
            for delivery_class in delivery_classes:
                with self.subTest(finality_key=finality_key, delivery_class=delivery_class):
                    fake_client = _DeliveryRoutingFakeClient()
                    adapter = self._adapter(fake_client)
                    result = await adapter.send(
                        chat_id="22" * 32,
                        content="Authoritative answer.",
                        metadata={"delivery_class": delivery_class, finality_key: True},
                    )
                    self.assertTrue(result.success)
                    self.assertEqual(fake_client.activities, [])
                    self.assertEqual(len(fake_client.final_sends), 1)

    async def test_delivery_class_applies_only_when_finality_is_missing(self):
        cases = (
            ("commentary", True),
            ("final", False),
            ("approval", False),
            ("operation", False),
            ("notice", False),
            ("mystery", False),
        )
        for delivery_class, expect_activity in cases:
            with self.subTest(delivery_class=delivery_class):
                fake_client = _DeliveryRoutingFakeClient()
                adapter = self._adapter(fake_client)
                result = await adapter.send(
                    chat_id="22" * 32,
                    content="Classified by delivery class.",
                    metadata={"delivery_class": delivery_class},
                )
                self.assertTrue(result.success)
                self.assertEqual(len(fake_client.activities), int(expect_activity))
                self.assertEqual(len(fake_client.final_sends), int(not expect_activity))

    async def test_commentary_rejects_activity_response_without_message_ids(self):
        fake_client = _DeliveryRoutingFakeClient()
        fake_client.activity_response = {"type": "ack"}
        adapter = self._adapter(fake_client)

        result = await adapter.send(
            chat_id="22" * 32,
            content="I'll check that.",
            metadata=self.NON_FINAL_COMMENTARY,
        )

        self.assertFalse(result.success)
        self.assertTrue(result.retryable)
        self.assertEqual(fake_client.final_sends, [])

    async def test_commentary_before_tool_sends_one_activity_zero_finals(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client)

        commentary = await adapter.send(
            chat_id="22" * 32,
            content="Let me search for that.",
            reply_to="33" * 32,
            metadata=self.NON_FINAL_COMMENTARY,
        )
        tool = await adapter.send(
            chat_id="22" * 32,
            content='* search: "titanium prices"',
            reply_to="33" * 32,
        )

        self.assertTrue(commentary.success)
        self.assertTrue(tool.success)
        self.assertEqual(len(fake_client.activities), 1)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.tool_events), 1)
        self.assertEqual(fake_client.activities[0][2]["text"], "Let me search for that.")

    async def test_final_answer_after_commentary_sends_exactly_one_kind_9(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client)

        commentary = await adapter.send(
            chat_id="22" * 32,
            content="Let me look that up.",
            metadata=self.NON_FINAL_COMMENTARY,
        )
        final = await adapter.send(
            chat_id="22" * 32,
            content="Here is the answer.",
            metadata={"is_turn_final": True, "delivery_class": "final"},
        )

        self.assertTrue(commentary.success)
        self.assertTrue(final.success)
        self.assertEqual(len(fake_client.activities), 1)
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertEqual(fake_client.final_sends[0][2], "Here is the answer.")

    async def test_missing_metadata_preserves_final_behavior(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client)

        result = await adapter.send(chat_id="22" * 32, content="pong", reply_to="33" * 32)

        self.assertTrue(result.success)
        self.assertEqual(fake_client.activities, [])
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertEqual(fake_client.final_sends[0][2], "pong")

    async def test_same_text_across_two_turns_emits_two_activities(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client)

        first = await adapter.send(
            chat_id="22" * 32,
            content="Checking...",
            metadata=self.NON_FINAL_COMMENTARY,
        )
        second = await adapter.send(
            chat_id="22" * 32,
            content="Checking...",
            metadata=self.NON_FINAL_COMMENTARY,
        )

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(len(fake_client.activities), 2)
        self.assertEqual(fake_client.final_sends, [])

    async def test_reply_parent_metadata_survives_direct_activity_mapping(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client)

        await adapter.send(
            chat_id="22" * 32,
            content="One moment.",
            metadata={
                **self.NON_FINAL_COMMENTARY,
                "reply_to_message_id": "33" * 32,
            },
        )

        self.assertEqual(fake_client.activities[0][2]["reply_to_message_id_hex"], "33" * 32)

    async def test_non_final_preview_stream_lifecycle_emits_one_activity(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client, quic_candidates=["quic://127.0.0.1:4433"])
        metadata = self.NON_FINAL_COMMENTARY

        preview = await adapter.send(
            chat_id="22" * 32,
            content="Let me search\u2589",
            reply_to="33" * 32,
            metadata=metadata,
        )
        self.assertTrue(preview.success)
        self.assertEqual(len(fake_client.stream_begins), 1)
        self.assertEqual(fake_client.activities, [])
        self.assertEqual(fake_client.final_sends, [])

        edited = await adapter.edit_message(
            "22" * 32,
            preview.message_id,
            "Let me search the docs\u2589",
            metadata=metadata,
        )
        self.assertTrue(edited.success)
        self.assertEqual(fake_client.activities, [])
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.final_sends, [])

        result = await adapter.edit_message(
            "22" * 32,
            preview.message_id,
            "Let me search the docs",
            finalize=True,
            metadata=metadata,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "aa" * 32)
        self.assertEqual(len(fake_client.activities), 1)
        self.assertEqual(fake_client.activities[0][2]["text"], "Let me search the docs")
        self.assertEqual(fake_client.activities[0][2]["reply_to_message_id_hex"], "33" * 32)
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.final_sends, [])

    async def test_non_final_draft_frames_then_sealed_send_emits_one_activity(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client, quic_candidates=["quic://127.0.0.1:4433"])
        metadata = self.NON_FINAL_COMMENTARY

        first = await adapter.send_draft(
            "22" * 32,
            1,
            "Let me search",
            metadata={
                **metadata,
                "parent_message_id_hex": "33" * 32,
            },
        )
        second = await adapter.send_draft(
            "22" * 32,
            1,
            "Let me search the docs",
            metadata=metadata,
        )

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(len(fake_client.stream_begins), 1)
        self.assertEqual(len(fake_client.stream_appends), 2)
        self.assertEqual(fake_client.activities, [])
        self.assertEqual(fake_client.final_sends, [])

        result = await adapter.send(
            chat_id="22" * 32,
            content="Let me search the docs",
            metadata=metadata,
        )
        self.assertTrue(result.success)
        self.assertEqual(len(fake_client.activities), 1)
        self.assertEqual(fake_client.activities[0][2]["text"], "Let me search the docs")
        self.assertEqual(fake_client.activities[0][2]["reply_to_message_id_hex"], "33" * 32)
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.final_sends, [])

    async def test_commentary_finalize_retryable_failure_preserves_stream_for_same_message_id(
        self,
    ):
        fake_client = _DeliveryRoutingFakeClient()
        fake_client.fail_next_activity = True
        adapter = self._adapter(fake_client, quic_candidates=["quic://127.0.0.1:4433"])
        metadata = self.NON_FINAL_COMMENTARY
        chat_id = "22" * 32

        preview = await adapter.send(
            chat_id=chat_id,
            content="Let me search\u2589",
            reply_to="33" * 32,
            metadata=metadata,
        )
        self.assertTrue(preview.success)
        message_id = preview.message_id
        self.assertIn(message_id, adapter._active_streams)

        first = await adapter.edit_message(
            chat_id,
            message_id,
            "Let me search the docs",
            finalize=True,
            metadata=metadata,
        )
        self.assertFalse(first.success)
        self.assertTrue(first.retryable)
        self.assertEqual(fake_client.activity_attempts, 1)
        self.assertEqual(len(fake_client.activities), 0)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.stream_cancels, [])
        self.assertIn(message_id, adapter._active_streams)

        second = await adapter.edit_message(
            chat_id,
            message_id,
            "Let me search the docs",
            finalize=True,
            metadata=metadata,
        )
        self.assertTrue(second.success)
        self.assertEqual(second.message_id, "aa" * 32)
        self.assertEqual(fake_client.activity_attempts, 2)
        self.assertEqual(len(fake_client.activities), 1)
        self.assertEqual(fake_client.activities[0][2]["text"], "Let me search the docs")
        self.assertEqual(fake_client.activities[0][2]["reply_to_message_id_hex"], "33" * 32)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "non-final commentary")])
        self.assertNotIn(message_id, adapter._active_streams)

    async def test_turn_final_true_streaming_path_still_finalizes_kind_9(self):
        fake_client = _DeliveryRoutingFakeClient()
        adapter = self._adapter(fake_client, quic_candidates=["quic://127.0.0.1:4433"])

        preview = await adapter.send("22" * 32, "Based on my research\u2589")
        final = await adapter.send(
            "22" * 32,
            "Based on my research, here's the answer",
            metadata={"is_turn_final": True, "delivery_class": "final"},
        )

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.activities, [])
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.final_sends, [])


def _install_stream_events_module():
    stream_events = types.ModuleType("gateway.stream_events")

    @dataclass
    class Commentary:
        text: str = ""

    @dataclass
    class MessageChunk:
        text: str = ""

    @dataclass
    class MessageStop:
        final: bool = True

    stream_events.Commentary = Commentary
    stream_events.MessageChunk = MessageChunk
    stream_events.MessageStop = MessageStop
    sys.modules["gateway.stream_events"] = stream_events
    return stream_events


class CommentaryRendererTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    def test_render_message_event_commentary_schedules_one_activity(self):
        stream_events = _install_stream_events_module()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=_DeliveryRoutingFakeClient(),
        )
        scheduled = []

        def track_schedule(chat_id, *, status, text, reply_to_message_id_hex=None):
            scheduled.append(
                {
                    "chat_id": chat_id,
                    "status": status,
                    "text": text,
                    "reply_to_message_id_hex": reply_to_message_id_hex,
                }
            )

        adapter._schedule_agent_activity = track_schedule

        class Sink:
            chat_id = "22" * 32
            _initial_reply_to_id = "33" * 32

        adapter.render_message_event(
            stream_events.Commentary(text="Checking sources."),
            Sink(),
        )

        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0]["status"], "commentary")
        self.assertEqual(scheduled[0]["text"], "Checking sources.")
        self.assertEqual(scheduled[0]["reply_to_message_id_hex"], "33" * 32)


class SendFinalIdempotencyRetryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    def _adapter(self, fake_client):
        return self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

    async def test_send_final_reuses_one_idempotency_key_across_bounded_retries(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.keys = []

            async def send_final(
                self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None
            ):
                self.keys.append(idempotency_key)
                # Fail the first two attempts with a retryable error, then succeed.
                if len(self.keys) < 3:
                    raise adapter_module.AgentControlError(
                        "transient", code="socket_io", retryable=True
                    )
                return {"type": "final_sent", "message_ids_hex": ["aa", "bb"]}

        fake_client = FakeClient()
        adapter = self._adapter(fake_client)

        result = await adapter.send(chat_id="22" * 32, content="pong", reply_to="33" * 32)

        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "bb")
        # Three attempts (2 retries) — the retry budget mirrors OpenClaw [100, 300]ms.
        self.assertEqual(len(fake_client.keys), 3)
        # One key, reused unchanged across every attempt, so the connector dedups
        # instead of double-posting an unrecallable encrypted message.
        self.assertTrue(fake_client.keys[0])
        self.assertEqual(len(set(fake_client.keys)), 1)

    async def test_send_final_retry_budget_is_bounded(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.keys = []

            async def send_final(
                self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None
            ):
                self.keys.append(idempotency_key)
                raise adapter_module.AgentControlError("down", code="socket_io", retryable=True)

        fake_client = FakeClient()
        adapter = self._adapter(fake_client)

        result = await adapter.send(chat_id="22" * 32, content="pong")

        self.assertFalse(result.success)
        self.assertTrue(result.retryable)
        # Initial attempt + the two bounded backoff retries, then it gives up.
        self.assertEqual(len(fake_client.keys), 3)
        self.assertEqual(len(set(fake_client.keys)), 1)

    async def test_send_final_non_retryable_error_fails_fast_without_retry(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.keys = []

            async def send_final(
                self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None
            ):
                self.keys.append(idempotency_key)
                raise adapter_module.AgentControlError(
                    "bad request", code="invalid_hex", retryable=False
                )

        fake_client = FakeClient()
        adapter = self._adapter(fake_client)

        result = await adapter.send(chat_id="22" * 32, content="pong")

        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        # A non-retryable error fails fast: exactly one attempt, no backoff loop.
        self.assertEqual(len(fake_client.keys), 1)


class ParityBehaviorTests(unittest.IsolatedAsyncioTestCase):
    """Coverage for the 8 OpenClaw-parity behaviors brought to the Hermes shim."""

    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    def _adapter(self, client, extra=None):
        merged = {"account_id_hex": "11" * 32, "profile_name_onboarding": False}
        if extra:
            merged.update(extra)
        return self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra=merged),
            client=client,
        )

    async def _render_inbound_timeline(self, messages):
        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message": {
                "message_id_hex": "33" * 32,
                "sender": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "text": "ping",
                "recorded_at": 1_721_000_000,
                "media": [],
            },
            "mentions_self": True,
        }

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                yield wire_event(event)

            async def timeline_list(self, account_id_hex, group_id_hex, **kwargs):
                return {
                    "type": "timeline_page",
                    "account_id_hex": account_id_hex,
                    "group_id_hex": group_id_hex,
                    "messages": messages,
                    "has_more_before": False,
                    "has_more_after": False,
                }

        adapter = self._adapter(FakeClient())
        await adapter._consume_inbound_once(drain=True)
        self.assertEqual(len(adapter.events), 1)
        return adapter.events[0].channel_context.splitlines()[0]

    async def test_timeline_context_small_page_needs_no_truncation(self):
        messages = [{"message_id_hex": str(i), "text": f"message-{i}"} for i in range(3)]

        rendered = await self._render_inbound_timeline(messages)
        prefix = "Marmot conversation history (untrusted): "
        fact = json.loads(rendered[len(prefix):])

        self.assertEqual(fact["messages"], messages)
        self.assertNotIn("messages_truncated", fact)
        self.assertLessEqual(
            len(rendered.encode("utf-8")),
            self.adapter_module.TIMELINE_CONTEXT_BYTE_LIMIT,
        )

    async def test_timeline_context_omits_one_oversized_record(self):
        rendered = await self._render_inbound_timeline(
            [{"message_id_hex": "newest", "text": "🙂" * 10_000}]
        )
        prefix = "Marmot conversation history (untrusted): "
        fact = json.loads(rendered[len(prefix):])

        self.assertEqual(fact["messages"], [])
        self.assertEqual(fact["omitted_message_count"], 1)
        self.assertEqual(fact["oversized_message_count"], 1)
        self.assertLessEqual(
            len(rendered.encode("utf-8")),
            self.adapter_module.TIMELINE_CONTEXT_BYTE_LIMIT,
        )

    async def test_timeline_context_counts_multiple_oversized_records(self):
        rendered = await self._render_inbound_timeline(
            [
                {"message_id_hex": "old-1", "text": "🙂" * 10_000},
                {"message_id_hex": "old-2", "text": "🙂" * 10_000},
                {"message_id_hex": "newest", "text": "kept"},
            ]
        )
        prefix = "Marmot conversation history (untrusted): "
        fact = json.loads(rendered[len(prefix):])

        self.assertEqual(
            [message["message_id_hex"] for message in fact["messages"]],
            ["newest"],
        )
        self.assertEqual(fact["omitted_message_count"], 2)
        self.assertEqual(fact["oversized_message_count"], 2)
        self.assertNotIn("old-1", rendered)
        self.assertNotIn("old-2", rendered)

    async def test_timeline_context_counts_oversized_records_outside_count_window(self):
        rendered = await self._render_inbound_timeline(
            [{"message_id_hex": str(i), "text": "🙂" * 10_000} for i in range(9)]
        )
        prefix = "Marmot conversation history (untrusted): "
        fact = json.loads(rendered[len(prefix):])

        self.assertEqual(fact["messages"], [])
        self.assertEqual(fact["omitted_message_count"], 9)
        self.assertEqual(fact["oversized_message_count"], 9)

    async def test_timeline_context_does_not_misclassify_metadata_displaced_record(self):
        final_message = {"message_id_hex": "final", "text": ""}
        single_fact = {
            "type": "chat_window",
            "order": "chronological",
            "relation": "before_current_message",
            "messages": [final_message],
            "messages_truncated": True,
            "omitted_message_count": 1,
        }
        base_bytes = len(
            f"{self.adapter_module._TIMELINE_CONTEXT_PREFIX}{json.dumps(single_fact, separators=(',', ':'))}".encode("utf-8")
        )
        final_message["text"] = "x" * (
            self.adapter_module.TIMELINE_CONTEXT_BYTE_LIMIT - base_bytes
        )
        self.assertFalse(
            self.adapter_module._timeline_message_exceeds_byte_limit(final_message)
        )

        messages = (
            [{"message_id_hex": "oversized", "text": "🙂" * 10_000}]
            + [{"message_id_hex": f"small-{i}", "text": ""} for i in range(7)]
            + [final_message]
        )
        rendered = await self._render_inbound_timeline(messages)
        prefix = "Marmot conversation history (untrusted): "
        fact = json.loads(rendered[len(prefix):])

        self.assertEqual(fact["messages"], [])
        self.assertEqual(fact["omitted_message_count"], 9)
        self.assertEqual(fact["oversized_message_count"], 1)

    # --- Behavior 1: append-only commits only after a successful append --------
    async def test_append_only_state_consistent_after_failed_stream_append(self):
        class FakeClient:
            def __init__(self):
                self.appends = []
                self.fail_next = True

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                self.appends.append((stream_id_hex, append_text))
                if self.fail_next:
                    self.fail_next = False
                    raise RuntimeError("transient append failure")
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self._adapter(
            fake_client,
            {"quic_candidates": ["quic://127.0.0.1:4433"]},
        )
        stream = await adapter._begin_live_stream("22" * 32)

        # First append fails: local append-only text and transcript must NOT advance.
        with self.assertRaises(RuntimeError):
            await stream.append_replacement("hello")
        self.assertEqual(stream.text.text, "")
        self.assertEqual(stream.transcript.chunk_count, 0)

        # The same text is re-appendable and now commits exactly once.
        await stream.append_replacement("hello")
        self.assertEqual(stream.text.text, "hello")
        self.assertEqual(stream.transcript.chunk_count, 1)
        self.assertEqual(fake_client.appends, [("55" * 32, "hello"), ("55" * 32, "hello")])

    async def test_pending_suffix_for_does_not_mutate_and_commit_advances(self):
        state = self.adapter_module.AppendOnlyTextState()
        self.assertEqual(state.pending_suffix_for("hello"), "hello")
        # No mutation yet.
        self.assertEqual(state.text, "")
        self.assertEqual(state.pending_suffix_for("hello"), "hello")
        state.commit("hello")
        self.assertEqual(state.text, "hello")
        self.assertEqual(state.pending_suffix_for("hello world"), " world")
        # Rejection semantics preserved on pending check.
        with self.assertRaises(self.adapter_module.NonAppendOnlyUpdate):
            state.pending_suffix_for("goodbye")

    # --- Behavior 2: client-side inbound message-id dedupe --------------------
    async def test_duplicate_inbound_message_id_is_dropped(self):
        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message_id_hex": "33" * 32,
            "sender_account_id_hex": "44" * 32,
            "text": "ping",
            "mentions_self": True,
        }

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for value in (event, dict(event)):
                    yield wire_event(value)

        adapter = self._adapter(FakeClient())
        await adapter._consume_inbound_once(drain=True)

        # The re-emitted duplicate is dropped: only one turn dispatched.
        self.assertEqual(len(adapter.events), 1)
        self.assertEqual(adapter.events[0].text, "ping")

    async def test_inbound_dedupe_records_id_before_dispatch(self):
        # Record-before-dispatch: even a slow turn cannot let a concurrent
        # duplicate (delivered mid-turn) start a second turn.
        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message_id_hex": "33" * 32,
            "sender_account_id_hex": "44" * 32,
            "text": "ping",
            "mentions_self": True,
        }
        adapter = self._adapter(client=object())

        gate = asyncio.Event()
        dispatched = []
        original = adapter.handle_message

        async def slow_handle(message):
            dispatched.append(message)
            await gate.wait()
            await original(message)

        adapter.handle_message = slow_handle
        first = asyncio.create_task(adapter._handle_control_event(wire_event(event)))
        await asyncio.sleep(0)
        # Let the per-group queue start the first turn so it is in-flight.
        await asyncio.sleep(0)
        # Duplicate arrives while the first turn is still in-flight.
        await adapter._handle_control_event(wire_event(event))
        gate.set()
        await first
        # Drain the per-group queue so the dispatched turn(s) complete before asserting.
        await adapter._inbound_queue.join()

        self.assertEqual(len(dispatched), 1)

    # --- Behavior 3: stream_progress wire type --------------------------------
    async def test_stream_progress_sends_progress_wire_type(self):
        requests = []

        async def handler(reader, writer):
            raw = await reader.readline()
            requests.append(json.loads(raw.decode("utf-8")))
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": requests[-1]["id"],
                    "type": "ack",
                },
            )
            writer.close()

        with tempfile.TemporaryDirectory() as tempdir:
            socket_path = str(Path(tempdir) / "wn-agent.sock")
            server = await asyncio.start_unix_server(handler, path=socket_path)
            try:
                client = self.adapter_module.MarmotAgentControlClient(socket_path)
                # The dead stream_tool method is gone; stream_progress exists.
                self.assertFalse(hasattr(client, "stream_tool"))
                response = await client.stream_progress("55" * 32, "33" * 32, "Working...")
            finally:
                server.close()
                await server.wait_closed()

        self.assertEqual(response["type"], "ack")
        self.assertEqual(requests[0]["type"], "stream_progress")
        self.assertEqual(requests[0]["stream_id_hex"], "55" * 32)
        self.assertEqual(requests[0]["text"], "Working...")

    # --- Behavior 4: sender_display_name + reply threading --------------------
    async def test_inbound_uses_sender_display_name_and_threads_reply(self):
        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message": {
                "message_id_hex": "33" * 32,
                "sender": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "text": "ping",
                "recorded_at": 1_721_000_000,
                "media": [],
            },
            "mentions_self": True,
            "reply_to": {
                "message_id_hex": "99" * 32,
                "availability": "available",
                "sender": {
                    "account_id_hex": "11" * 32,
                    "display_name": "Hermes Agent",
                    "is_self": True,
                },
                "recorded_at": 1_720_999_900,
                "text_excerpt": "earlier answer",
                "text_truncated": False,
                "attachments": [],
                "attachments_truncated": False,
            },
        }

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                yield wire_event(event)

            async def timeline_list(self, account_id_hex, group_id_hex, **kwargs):
                return {
                    "type": "timeline_page",
                    "account_id_hex": account_id_hex,
                    "group_id_hex": group_id_hex,
                    "messages": [
                        {
                            "message_id_hex": f"{index:064x}",
                            "sender": {
                                "account_id_hex": "44" * 32,
                                "display_name": "Alice",
                                "is_self": False,
                            },
                            "direction": "received",
                            "kind": 9,
                            "recorded_at": 1_720_999_800 + index,
                            "observed_at": 1_720_999_801 + index,
                            "availability": "available",
                            "text": "x" * 1_500,
                            "text_truncated": False,
                            "attachments_truncated": False,
                            "reactions_truncated": False,
                        }
                        for index in range(20)
                    ],
                    "has_more_before": False,
                    "has_more_after": False,
                }

        adapter = self._adapter(FakeClient())
        await adapter._consume_inbound_once(drain=True)

        self.assertEqual(len(adapter.events), 1)
        delivered = adapter.events[0]
        # Display name used for the source user_name.
        self.assertEqual(delivered.source.user_name, "Alice")
        # Reply threads to the inbound message id (source.message_id).
        self.assertEqual(delivered.source.message_id, "33" * 32)
        self.assertEqual(delivered.message_id, "33" * 32)
        self.assertEqual(delivered.timestamp.timestamp(), 1_721_000_000)
        self.assertEqual(delivered.reply_to_message_id, "99" * 32)
        self.assertEqual(delivered.reply_to_text, "earlier answer")
        self.assertEqual(delivered.reply_to_author_id, "11" * 32)
        self.assertEqual(delivered.reply_to_author_name, "Hermes Agent")
        self.assertTrue(delivered.reply_to_is_own_message)
        # The internal normalized shape retains the routing id as well.
        self.assertEqual(delivered.raw_message.get("reply_to_message_id_hex"), "99" * 32)
        self.assertIn('"type":"chat_window"', delivered.channel_context)
        timeline_context = delivered.channel_context.splitlines()[0]
        timeline_prefix = "Marmot conversation history (untrusted): "
        timeline_fact = json.loads(timeline_context[len(timeline_prefix):])
        self.assertEqual(
            [message["message_id_hex"] for message in timeline_fact["messages"]],
            [f"{index:064x}" for index in range(12, 20)],
        )
        self.assertEqual(timeline_fact["omitted_message_count"], 12)
        self.assertLessEqual(
            len(timeline_context.encode("utf-8")),
            self.adapter_module.TIMELINE_CONTEXT_BYTE_LIMIT,
        )
        self.assertIn('"type":"referenced_message"', delivered.channel_context)
        self.assertIn('"text_excerpt":"earlier answer"', delivered.channel_context)
        self.assertIn('"display_name":"Hermes Agent"', delivered.channel_context)

    async def test_inbound_falls_back_to_marmot_name_without_display_name(self):
        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message_id_hex": "33" * 32,
            "sender_account_id_hex": "44" * 32,
            "text": "ping",
            "mentions_self": True,
            "sender_display_name": "   ",
        }

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                yield wire_event(event)

        adapter = self._adapter(FakeClient())
        await adapter._consume_inbound_once(drain=True)

        self.assertEqual(adapter.events[0].source.user_name, "Marmot 444444444444")

    # --- Behavior 5: ambient delete / group-state context + dedupe -----------
    def test_group_state_change_sentences_match_reference(self):
        sentence = self.adapter_module.group_state_change_sentence
        self.assertEqual(sentence("member_added"), "A member was added to the group.")
        self.assertEqual(sentence("member_removed"), "A member was removed from the group.")
        self.assertEqual(sentence("member_left"), "A member left the group.")
        self.assertEqual(sentence("admin_added"), "A member was made a group admin.")
        self.assertEqual(sentence("admin_removed"), "A member is no longer a group admin.")
        self.assertEqual(sentence("group_renamed", "Crew"), 'The group was renamed to "Crew".')
        self.assertEqual(sentence("group_renamed", "  "), "The group was renamed.")
        self.assertEqual(sentence("group_avatar_changed"), "The group avatar was changed.")
        self.assertEqual(
            sentence("disappearing_timer_changed"),
            "The disappearing-message timer was changed.",
        )
        self.assertEqual(sentence("something_else"), "The group state changed.")

    async def test_ambient_events_are_quiet_and_attach_to_next_inbound(self):
        # Ambient events (a deletion, a group-state change) must NEVER start an
        # agent turn. They are buffered per group and prepended to the next real
        # inbound message for that group as channel_context. A duplicate deletion
        # is deduped by context key.
        events = [
            {
                "type": "message_deleted",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "event_id_hex": "d1" * 32,
                "target_message_id_hex": "33" * 32,
                "actor": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "recorded_at": 1_721_000_000,
                "target": {
                    "message_id_hex": "33" * 32,
                    "availability": "deleted",
                },
            },
            {
                "type": "message_deleted",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "event_id_hex": "d1" * 32,
                "target_message_id_hex": "33" * 32,
                "actor": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "recorded_at": 1_721_000_000,
                "target": {
                    "message_id_hex": "33" * 32,
                    "availability": "deleted",
                },
            },
            {
                "type": "message_edited",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "event_id_hex": "e1" * 32,
                "target_message_id_hex": "33" * 32,
                "actor": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "replacement_text": "edited",
                "recorded_at": 1_721_000_001,
                "target": {
                    "message_id_hex": "33" * 32,
                    "availability": "available",
                },
            },
            {
                "type": "reaction_added",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "event_id_hex": "e2" * 32,
                "target_message_id_hex": "33" * 32,
                "actor": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "emoji": "👍",
                "recorded_at": 1_721_000_002,
                "target": {
                    "message_id_hex": "33" * 32,
                    "availability": "available",
                },
            },
            {
                "type": "reaction_removed",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "event_id_hex": "e3" * 32,
                "reaction_event_id_hex": "e2" * 32,
                "target_message_id_hex": "33" * 32,
                "actor": {
                    "account_id_hex": "44" * 32,
                    "display_name": "Alice",
                    "is_self": False,
                },
                "emoji": "👍",
                "recorded_at": 1_721_000_003,
                "target": {
                    "message_id_hex": "33" * 32,
                    "availability": "available",
                },
            },
            {
                "type": "group_state_changed",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "change": "group_renamed",
                "detail": "Crew",
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a1" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hello there",
                "mentions_self": True,
            },
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for value in events:
                    yield wire_event(value)

        adapter = self._adapter(FakeClient())
        await adapter._consume_inbound_once(drain=True)

        # Only the real inbound message reached handle_message (one agent turn);
        # the ambient events did NOT trigger turns of their own.
        self.assertEqual(len(adapter.events), 1)
        triggered = adapter.events[0]
        self.assertEqual(triggered.text, "hello there")
        # No ambient event masquerades as a triggering message: the dispatched
        # event is a normal inbound_message, never an ambient flag.
        self.assertEqual(triggered.raw_message.get("type"), "inbound_message")
        self.assertNotIn("marmot_ambient", triggered.raw_message)
        # The distinct ambient facts (deletion deduped to one, mutations, rename) are
        # carried as quiet channel_context on the next inbound turn, in order.
        self.assertIn('"type":"message_deleted"', triggered.channel_context)
        self.assertEqual(triggered.channel_context.count('"type":"message_deleted"'), 1)
        self.assertIn('"type":"message_edited"', triggered.channel_context)
        self.assertIn('"type":"reaction_added"', triggered.channel_context)
        self.assertIn('"type":"reaction_removed"', triggered.channel_context)
        self.assertTrue(
            triggered.channel_context.endswith('The group was renamed to "Crew".')
        )
        # Buffer was drained: a second message in the group carries no stale context.
        self.assertEqual(adapter._take_pending_ambient_context("22" * 32), None)

    async def test_ambient_event_never_invokes_message_handler(self):
        # Regression guard for the adversarial finding: an ambient event must not
        # call handle_message(). If only ambient events arrive (no inbound text),
        # no agent turn is ever started and the fact is merely buffered/logged.
        handler_calls = []

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                yield {
                    "type": "message_deleted",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                    "event_id_hex": "d1" * 32,
                    "target_message_id_hex": "33" * 32,
                    "actor": {
                        "account_id_hex": "44" * 32,
                        "display_name": None,
                        "is_self": False,
                    },
                    "recorded_at": 1_721_000_000,
                    "target": {
                        "message_id_hex": "33" * 32,
                        "availability": "deleted",
                    },
                }

        adapter = self._adapter(FakeClient())

        async def fail_if_called(event):
            handler_calls.append(event)

        adapter.handle_message = fail_if_called  # type: ignore[assignment]
        await adapter._consume_inbound_once()

        self.assertEqual(handler_calls, [], "ambient event must not invoke handle_message")
        # The fact is buffered for a later real message rather than dropped.
        context = adapter._take_pending_ambient_context("22" * 32)
        self.assertIn('"type":"message_deleted"', context)
        self.assertNotIn("plaintext", context)

    async def test_ambient_context_is_bounded_and_survives_failed_turn(self):
        class FakeClient:
            pass

        adapter = self._adapter(FakeClient())
        group_id = "22" * 32
        for index in range(20):
            adapter._append_pending_ambient_context(group_id, f"fact-{index}")

        pending_facts = list(adapter._pending_ambient_context[group_id])
        pending = "\n".join(pending_facts)
        self.assertEqual(len(pending_facts), 16)
        self.assertNotIn("fact-3\n", pending)
        self.assertTrue(pending.startswith("fact-4\n"))
        self.assertTrue(pending.endswith("fact-19"))

        async def fail_turn(event):
            adapter._append_pending_ambient_context(group_id, "fact-new-on-failure")
            raise RuntimeError("synthetic turn failure")

        adapter.handle_message = fail_turn  # type: ignore[assignment]
        await adapter._dispatch_inbound_message(
            self.adapter_module._normalize_inbound_message_event(
                wire_event(
                    {
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_id,
                        "message_id_hex": "a1" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "hello",
                        "mentions_self": True,
                    }
                )
            )
        )
        retained = adapter._pending_ambient_context[group_id]
        self.assertEqual(len(retained), 16)
        self.assertNotIn("fact-4", retained)
        self.assertEqual(retained[-1], "fact-new-on-failure")

        adapter._pending_ambient_context[group_id] = [
            f"success-fact-{index}" for index in range(16)
        ]
        delivered_context = []

        async def successful_turn(event):
            delivered_context.append(event.channel_context)
            adapter._append_pending_ambient_context(group_id, "fact-new-on-success")

        adapter.handle_message = successful_turn  # type: ignore[assignment]
        await adapter._dispatch_inbound_message(
            self.adapter_module._normalize_inbound_message_event(
                wire_event(
                    {
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_id,
                        "message_id_hex": "a2" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "hello again",
                        "mentions_self": True,
                    }
                )
            )
        )
        self.assertIn("success-fact-0", delivered_context[0])
        self.assertEqual(
            adapter._pending_ambient_context[group_id],
            ["fact-new-on-success"],
        )

        for index in range(257):
            adapter._append_pending_ambient_context(
                f"{index:064x}",
                f"group-fact-{index}",
            )
        self.assertEqual(len(adapter._pending_ambient_context), 256)
        self.assertNotIn(f"{0:064x}", adapter._pending_ambient_context)
        self.assertIn(f"{256:064x}", adapter._pending_ambient_context)

    # --- Behavior 6: optional debounce coalescing preserves mentions+media ----
    async def test_debounce_coalesces_and_preserves_mentions_and_media(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a1" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "first",
                "mentions_self": False,
                "media": [{"file_name": "a.png"}],
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a2" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "",
                "mentions_self": True,
                "media": [{"file_name": "b.png"}],
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a3" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "third",
                "mentions_self": False,
            },
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for value in events:
                    yield wire_event(value)

        adapter = self._adapter(FakeClient(), {"debounce_ms": 5})
        await adapter._consume_inbound_once()
        # Wait for the debounce flush task to fire, then drain the per-group queue
        # (the flush enqueues the coalesced turn onto it).
        for _ in range(200):
            if adapter.events:
                break
            await asyncio.sleep(0.005)
        await adapter._inbound_queue.join()

        self.assertEqual(len(adapter.events), 1)
        merged = adapter.events[0]
        # Empty parts skipped, non-empty newline-joined.
        self.assertEqual(merged.text, "first\nthird")
        # mentions_self OR'd across the batch.
        self.assertTrue(merged.raw_message.get("mentions_self"))
        # Media concatenated across the batch (never dropped).
        self.assertEqual(
            merged.raw_message.get("media"),
            [{"file_name": "a.png"}, {"file_name": "b.png"}],
        )
        # Last message's id is the representative.
        self.assertEqual(merged.message_id, "a3" * 32)

    async def test_debounce_disabled_is_one_event_one_dispatch(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a1" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "first",
                "mentions_self": True,
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "a2" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "second",
                "mentions_self": True,
            },
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for value in events:
                    yield wire_event(value)

        adapter = self._adapter(FakeClient())  # debounce disabled by default
        await adapter._consume_inbound_once(drain=True)

        self.assertEqual([event.text for event in adapter.events], ["first", "second"])

    def test_resolve_debounce_ms_reads_config_and_clamps(self):
        resolve = self.adapter_module.resolve_debounce_ms
        self.assertEqual(resolve({}), 0)
        self.assertEqual(resolve({"debounce_ms": 250}), 250)
        self.assertEqual(resolve({"debounce_ms": "-5"}), 0)
        self.assertEqual(resolve({"debounce_ms": "junk"}), 0)

    # --- Behavior 7: reconnect backoff + jitter -------------------------------
    def test_reconnect_backoff_ms_boundaries(self):
        backoff = self.adapter_module.reconnect_backoff_ms
        # base <= 0 -> 0.
        self.assertEqual(backoff(0, 0, 30000), 0)
        # attempt 0: ceiling collapses to base -> exactly base (no jitter).
        self.assertEqual(backoff(0, 1000, 30000, rand=lambda: 0.5), 1000)
        # attempt 1: ceiling = 2000; rand 0 -> base, rand 1 -> ceiling.
        self.assertEqual(backoff(1, 1000, 30000, rand=lambda: 0.0), 1000)
        self.assertEqual(backoff(1, 1000, 30000, rand=lambda: 1.0), 2000)
        self.assertEqual(backoff(1, 1000, 30000, rand=lambda: 0.5), 1500)
        # Cap clamps the ceiling.
        self.assertEqual(backoff(10, 1000, 3000, rand=lambda: 1.0), 3000)
        # cap below base collapses to base.
        self.assertEqual(backoff(5, 1000, 500, rand=lambda: 1.0), 1000)

    async def test_reconnect_attempt_resets_after_healthy_subscription(self):
        # A healthy subscription (yields an event) followed by an error must
        # reset the backoff attempt counter so the next failure starts at base.
        attempts = {"n": 0}
        delays = []

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                await asyncio.sleep(0)
                if attempts["n"] == 1:
                    # Healthy: yields one message, then raises -> reconnect.
                    yield wire_event({
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": "22" * 32,
                        "message_id_hex": "33" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "healthy",
                        "mentions_self": True,
                    })
                    raise RuntimeError("dropped after healthy")
                else:
                    await asyncio.sleep(3600)
                    return

        adapter = self._adapter(FakeClient())

        # Record the computed backoff (ms) the loop chooses, and return 0 so the
        # test never actually sleeps the backoff window. This avoids patching the
        # shared asyncio.sleep (which the loop uses with the returned value).
        real_backoff = self.adapter_module.reconnect_backoff_ms

        def recording_backoff(attempt, base_ms, cap_ms, rand=None):
            value = real_backoff(attempt, base_ms, cap_ms, rand=rand)
            delays.append((attempt, value))
            return 0

        self.adapter_module.reconnect_backoff_ms = recording_backoff
        try:
            loop_task = asyncio.ensure_future(adapter._consume_inbound_loop(rand=lambda: 0.0))
            for _ in range(300):
                if attempts["n"] >= 2 and delays:
                    break
                await asyncio.sleep(0.005)
        finally:
            self.adapter_module.reconnect_backoff_ms = real_backoff
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        # The subscription was healthy (delivered the message), so after its
        # failure the backoff attempt counter resets to 0 -> base delay (1000ms).
        self.assertEqual(len(adapter.events), 1)
        self.assertEqual(adapter.events[0].text, "healthy")
        self.assertEqual(delays[0], (0, 1000))

    async def test_clean_eof_subscription_backs_off_instead_of_hot_looping(self):
        # Regression guard for the adversarial finding: a connector that accepts,
        # acks, then immediately closes the inbound stream with a clean EOF (the
        # async generator returns without yielding) must NOT pin the loop in a
        # hot resubscribe spin. A clean return is treated as a dropped
        # subscription and runs the SAME backoff path as an error; because the
        # subscription never established, the attempt counter grows so the
        # computed delay backs off geometrically (0ms gets only the first attempt).
        attempts = {"n": 0}
        delays = []

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                await asyncio.sleep(0)
                # Never yields: a clean EOF on the inbound stream.
                return
                yield  # pragma: no cover - makes this an async generator

        adapter = self._adapter(FakeClient())

        real_backoff = self.adapter_module.reconnect_backoff_ms

        def recording_backoff(attempt, base_ms, cap_ms, rand=None):
            value = real_backoff(attempt, base_ms, cap_ms, rand=rand)
            delays.append((attempt, value))
            # Return 0 so the test never actually sleeps; we only assert on the
            # computed (attempt -> delay) sequence to prove the backoff grows.
            return 0

        self.adapter_module.reconnect_backoff_ms = recording_backoff
        try:
            loop_task = asyncio.ensure_future(adapter._consume_inbound_loop(rand=lambda: 1.0))
            for _ in range(300):
                if len(delays) >= 4:
                    break
                await asyncio.sleep(0.005)
        finally:
            self.adapter_module.reconnect_backoff_ms = real_backoff
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        # The clean EOF entered the backoff path every reconnect (not else:continue),
        # so the loop never opened a subscription without first consulting backoff.
        self.assertGreaterEqual(attempts["n"], 1)
        self.assertGreaterEqual(len(delays), 4)
        # Attempt counter advances on each clean-EOF reconnect (never reset, since
        # the subscription never established): 0, 1, 2, 3, ...
        self.assertEqual([a for a, _ in delays[:4]], [0, 1, 2, 3])
        # Delay grows geometrically: only attempt 0 is the base; later attempts
        # are strictly larger, so the loop cannot spin at a flat cadence.
        self.assertEqual(delays[0][1], 1000)
        self.assertGreater(delays[1][1], delays[0][1])
        self.assertGreater(delays[2][1], delays[1][1])

    # --- Behavior 8: preview vs durable timeout -------------------------------
    async def test_preview_ops_use_short_timeout_durable_uses_full(self):
        seen = []

        class TimeoutRecordingClient(self.adapter_module.MarmotAgentControlClient):
            async def request(
                self,
                payload,
                *,
                request_id=None,
                timeout=None,
                response_timeout=self.adapter_module._DEFAULT_READ_TIMEOUT,
            ):
                seen.append((payload.get("type"), timeout))
                return {"type": "ack", "message_ids_hex": ["77" * 32], "stream_id_hex": "55" * 32, "start_message_id_hex": "66" * 32, "quic_candidates": []}

        client = TimeoutRecordingClient(
            "/tmp/does-not-matter.sock",
            request_timeout=30.0,
            preview_request_timeout=8.0,
        )
        self.assertEqual(client.preview_request_timeout, 8.0)

        await client.stream_begin("11" * 32, "22" * 32, quic_candidates=["quic://x"])
        await client.stream_append("55" * 32, "33" * 32, "hi")
        await client.stream_status("55" * 32, "33" * 32, "thinking")
        await client.stream_progress("55" * 32, "33" * 32, "Working...")
        await client.stream_cancel("55" * 32, "33" * 32, "done")
        await client.stream_finalize("55" * 32, "33" * 32, "final", "ab" * 32, 1)
        await client.send_final("11" * 32, "22" * 32, "durable")

        by_type = dict(seen)
        for preview_op in ("stream_begin", "stream_append", "stream_status", "stream_progress", "stream_cancel"):
            self.assertEqual(by_type[preview_op], 8.0, preview_op)
        # Durable ops use the full timeout (request() default -> None -> request_timeout).
        self.assertIsNone(by_type["stream_finalize"])
        self.assertIsNone(by_type["send_final"])


class FinalizeFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_stream_begin_retries_with_the_same_request_id(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.request_ids = []

            async def stream_begin(
                self,
                account_id_hex,
                group_id_hex,
                *,
                stream_id_hex=None,
                parent_message_id_hex=None,
                quic_candidates=(),
                request_id=None,
            ):
                self.request_ids.append(request_id)
                if len(self.request_ids) == 1:
                    raise adapter_module.AgentControlError(
                        "timed out waiting for stream begin",
                        code="timeout",
                        retryable=True,
                    )
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

        client = FakeClient()
        stream = await adapter_module.MarmotLiveStream.begin(
            client=client,
            account_id_hex="11" * 32,
            group_id_hex="22" * 32,
            quic_candidates=(),
            chunk_bytes=1024,
        )

        self.assertTrue(client.request_ids[0])
        self.assertEqual(client.request_ids[1], client.request_ids[0])
        self.assertEqual(stream.stream_capability, "33" * 32)

    async def test_stream_finalize_retries_retryable_failure_with_same_idempotency_key(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                return {"type": "ack"}

            async def stream_finalize(
                self,
                stream_id_hex,
                stream_capability,
                final_text,
                transcript_hash_hex,
                chunk_count,
                idempotency_key=None,
            ):
                self.stream_finalizes.append(
                    (stream_id_hex, final_text, transcript_hash_hex, chunk_count, idempotency_key)
                )
                if len(self.stream_finalizes) == 1:
                    raise adapter_module.AgentControlError(
                        "timed out waiting for stream finalize",
                        code="timeout",
                        retryable=True,
                    )
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex, idempotency_key))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        preview = await adapter.send("22" * 32, "hello\u2589")
        final = await adapter.send("22" * 32, "hello world")

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.stream_finalizes), 2)
        self.assertTrue(fake_client.stream_finalizes[0][4])
        self.assertEqual(fake_client.stream_finalizes[1][4], fake_client.stream_finalizes[0][4])

    async def test_finalize_rejection_falls_back_to_plain_send_final(self):
        adapter_module = self.adapter_module

        class FakeClient:
            def __init__(self):
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=(), request_id=None):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "stream_capability": "33" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, stream_capability, append_text):
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, stream_capability, final_text, transcript_hash_hex, chunk_count, idempotency_key=None):
                raise adapter_module.AgentControlError(
                    "transcript hash mismatch",
                    code="stream_finalize_rejected",
                )

            async def stream_cancel(self, stream_id_hex, stream_capability, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

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

        preview = await adapter.send("22" * 32, "hello\u2589")
        final = await adapter.send("22" * 32, "hello world")

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertEqual(fake_client.final_sends[0][2], "hello world")
        self.assertTrue(fake_client.stream_cancels)


class MediaSupportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_inbound_media_download_populates_ordered_message_event(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first_source = Path(tmpdir) / "inbound.png"
            second_source = Path(tmpdir) / "inbound.jpg"
            first_source.write_bytes(b"png")
            second_source.write_bytes(b"jpg")
            sources = {
                "inbound.png": (first_source, "image/png"),
                "inbound.jpg": (second_source, "image/jpeg"),
            }

            class FakeClient:
                async def download_media(self, account_id_hex, group_id_hex, media):
                    source, media_type = sources[media["file_name"]]
                    return {
                        "type": "media_downloaded",
                        "path": str(source),
                        "media_type": media_type,
                        "file_name": media["file_name"],
                        "size_bytes": source.stat().st_size,
                    }

            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "11" * 32, "home": tmpdir}),
                client=FakeClient(),
            )
            adapter.handle_message = unittest.mock.AsyncMock()

            base_media = {
                "ciphertext_sha256": "aa",
                "plaintext_sha256": "bb",
                "nonce_hex": "cc",
                "version": "1",
                "source_epoch": 1,
                "locators": [],
            }
            event = {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "photo album",
                "mentions_self": True,
                "media": [
                    {**base_media, "file_name": "inbound.png", "media_type": "image/png"},
                    {**base_media, "file_name": "inbound.jpg", "media_type": "image/jpeg"},
                ],
            }
            await adapter._dispatch_inbound_message(event)

            dispatched = adapter.handle_message.await_args.args[0]
            staged_root = str(Path(tmpdir) / "dev" / "inbound-media")
            self.assertEqual(len(dispatched.media_urls), 2)
            self.assertTrue(all(url.startswith(staged_root) for url in dispatched.media_urls))
            self.assertEqual(dispatched.media_types, ["image/png", "image/jpeg"])
            self.assertFalse(first_source.exists())
            self.assertFalse(second_source.exists())

    async def test_outbound_send_image_file_routes_to_send_media(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            media_dir = Path(tmpdir) / "dev" / "inbound-media"
            media_dir.mkdir(parents=True)
            image_path = media_dir / "out.png"
            image_path.write_bytes(b"png")

            class FakeClient:
                def __init__(self):
                    self.media_sends = []

                async def send_media(
                    self,
                    account_id_hex,
                    group_id_hex,
                    attachments,
                    *,
                    caption=None,
                    idempotency_key=None,
                ):
                    self.assert_staged = Path(attachments[0]["path"]).read_bytes()
                    self.media_sends.append(
                        (account_id_hex, group_id_hex, attachments, caption, idempotency_key)
                    )
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "11" * 32, "home": tmpdir}),
                client=fake_client,
            )
            result = await adapter.send_image_file("22" * 32, str(image_path), caption="look")

            self.assertTrue(result.success)
            self.assertEqual(len(fake_client.media_sends), 1)
            staged_path = Path(fake_client.media_sends[0][2][0]["path"])
            self.assertEqual(fake_client.assert_staged, b"png")
            self.assertTrue(str(staged_path).startswith(str(Path(tmpdir) / "dev" / "outbound-media")))
            self.assertNotEqual(staged_path, image_path)
            self.assertFalse(staged_path.exists())
            self.assertTrue(image_path.exists())
            self.assertEqual(fake_client.media_sends[0][3], "look")

    async def test_outbound_send_multiple_images_routes_one_ordered_batch_to_send_media(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            media_dir = Path(tmpdir) / "dev" / "inbound-media"
            media_dir.mkdir(parents=True)
            first_path = media_dir / "first.png"
            second_path = media_dir / "second.jpg"
            first_path.write_bytes(b"first")
            second_path.write_bytes(b"second")

            class FakeClient:
                def __init__(self):
                    self.media_sends = []
                    self.staged_bytes = []

                async def send_media(
                    self,
                    account_id_hex,
                    group_id_hex,
                    attachments,
                    *,
                    caption=None,
                    idempotency_key=None,
                ):
                    self.staged_bytes = [Path(item["path"]).read_bytes() for item in attachments]
                    self.media_sends.append(
                        (account_id_hex, group_id_hex, attachments, caption, idempotency_key)
                    )
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "11" * 32, "home": tmpdir}),
                client=fake_client,
            )
            result = await adapter.send_multiple_images(
                "22" * 32,
                [(f"file://{first_path}", "album caption"), (f"file://{second_path}", "")],
            )

            self.assertIsNone(result)
            self.assertEqual(len(fake_client.media_sends), 1)
            sent = fake_client.media_sends[0]
            self.assertEqual(fake_client.staged_bytes, [b"first", b"second"])
            self.assertEqual(
                [(item["file_name"], item["media_type"]) for item in sent[2]],
                [("first.png", "image/png"), ("second.jpg", "image/jpeg")],
            )
            self.assertEqual(sent[3], "album caption")
            self.assertTrue(sent[4])
            self.assertTrue(all(not Path(item["path"]).exists() for item in sent[2]))
            self.assertTrue(first_path.exists())
            self.assertTrue(second_path.exists())

    async def test_multiple_images_preflight_rejects_mixed_valid_and_invalid_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            valid = root / "valid.png"
            valid.write_bytes(b"valid")

            class FakeClient:
                def __init__(self):
                    self.calls = 0

                async def send_media(self, *args, **kwargs):
                    self.calls += 1
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            with self.assertRaisesRegex(self.adapter_module.AgentControlError, "not a readable file"):
                await adapter.send_multiple_images(
                    "22" * 32,
                    [(valid.as_uri(), "caption"), ((root / "missing.png").as_uri(), "")],
                )

            self.assertEqual(fake_client.calls, 0)
            self.assertEqual(list(adapter._outbound_media_dir.iterdir()), [])

    async def test_multiple_images_preflight_oserror_redacts_local_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "private.png"
            image.write_bytes(b"private")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=unittest.mock.AsyncMock(),
            )
            private_error = OSError(f"stat failed for {image}")

            with (
                unittest.mock.patch.object(self.adapter_module.Path, "stat", side_effect=private_error),
                unittest.mock.patch.object(self.adapter_module.logger, "debug") as debug_log,
                self.assertRaises(self.adapter_module.AgentControlError) as raised,
            ):
                await adapter.send_multiple_images("22" * 32, [(image.as_uri(), "caption")])

            self.assertEqual(str(raised.exception), "Marmot media preflight failed")
            self.assertNotIn(str(image), str(raised.exception))
            self.assertNotIn(str(image), repr(debug_log.call_args_list))

    async def test_multiple_images_preserves_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "same.png"
            image.write_bytes(b"same")

            class FakeClient:
                def __init__(self):
                    self.attachments = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.attachments = attachments
                    self.asserted_bytes = [Path(item["path"]).read_bytes() for item in attachments]
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            await adapter.send_multiple_images(
                "22" * 32,
                [(image.as_uri(), "caption"), (image.as_uri(), "")],
            )

            self.assertEqual([item["file_name"] for item in fake_client.attachments], ["same.png", "same.png"])
            self.assertEqual(fake_client.asserted_bytes, [b"same", b"same"])
            self.assertNotEqual(fake_client.attachments[0]["path"], fake_client.attachments[1]["path"])

    async def test_multiple_images_count_and_byte_boundaries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            paths = []
            for index in range(4):
                path = root / f"{index}.png"
                path.write_bytes(b"1234")
                paths.append(path)

            class FakeClient:
                def __init__(self):
                    self.calls = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.calls.append(attachments)
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            with (
                unittest.mock.patch.object(self.adapter_module, "MAX_OUTBOUND_MEDIA_ATTACHMENTS", 3),
                unittest.mock.patch.object(self.adapter_module, "MAX_OUTBOUND_MEDIA_FILE_BYTES", 4),
                unittest.mock.patch.object(self.adapter_module, "MAX_OUTBOUND_MEDIA_BATCH_BYTES", 12),
            ):
                await adapter.send_multiple_images(
                    "22" * 32,
                    [(path.as_uri(), "") for path in paths[:3]],
                )
                with self.assertRaisesRegex(self.adapter_module.AgentControlError, "at most 3"):
                    await adapter.send_multiple_images(
                        "22" * 32,
                        [(path.as_uri(), "") for path in paths],
                    )
                oversize = root / "oversize.png"
                oversize.write_bytes(b"12345")
                with self.assertRaisesRegex(self.adapter_module.AgentControlError, "blob size limit"):
                    await adapter.send_multiple_images("22" * 32, [(oversize.as_uri(), "")])
                with unittest.mock.patch.object(
                    self.adapter_module,
                    "MAX_OUTBOUND_MEDIA_BATCH_BYTES",
                    7,
                ):
                    with self.assertRaisesRegex(self.adapter_module.AgentControlError, "total size limit"):
                        await adapter.send_multiple_images(
                            "22" * 32,
                            [(path.as_uri(), "") for path in paths[:2]],
                        )

            self.assertEqual(len(fake_client.calls), 1)

    async def test_multiple_images_pins_open_source_across_ancestor_symlink_replacement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            allowed = base / "allowed"
            album = allowed / "album"
            album.mkdir(parents=True)
            image = album / "image.png"
            image.write_bytes(b"approved")
            outside = base / "outside"
            outside.mkdir()
            (outside / "image.png").write_bytes(b"private")

            class FakeClient:
                staged_bytes = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.staged_bytes = [Path(item["path"]).read_bytes() for item in attachments]
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(allowed)],
                    }
                ),
                client=fake_client,
            )
            real_stage = self.adapter_module.stage_outbound_media_file
            replaced = False

            def replace_parent_then_stage(source, staging_root, **kwargs):
                nonlocal replaced
                if not replaced:
                    replaced = True
                    album.rename(allowed / "album-original")
                    album.symlink_to(outside, target_is_directory=True)
                return real_stage(source, staging_root, **kwargs)

            with unittest.mock.patch.object(
                self.adapter_module,
                "stage_outbound_media_file",
                side_effect=replace_parent_then_stage,
            ):
                await adapter.send_multiple_images("22" * 32, [(image.as_uri(), "caption")])

            self.assertEqual(fake_client.staged_bytes, [b"approved"])

    async def test_pinned_media_root_rejects_root_path_replaced_by_outside_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            allowed = base / "allowed"
            allowed.mkdir()
            image = allowed / "image.png"
            image.write_bytes(b"approved")
            outside = base / "outside"
            outside.mkdir()
            (outside / "image.png").write_bytes(b"private")
            pinned_roots = self.adapter_module.pin_allowed_media_roots([allowed])
            allowed.rename(base / "allowed-original")
            allowed.symlink_to(outside, target_is_directory=True)

            try:
                with self.assertRaisesRegex(
                    self.adapter_module.AgentControlError,
                    "outside allowed local roots",
                ):
                    self.adapter_module.open_outbound_media_source(image, pinned_roots)
            finally:
                for _, directory_fd in pinned_roots:
                    self.adapter_module.os.close(directory_fd)

    async def test_multiple_images_enforces_limit_against_bytes_copied_after_growth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "growing.png"
            image.write_bytes(b"1234")
            client = unittest.mock.AsyncMock()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=client,
            )
            real_stage = self.adapter_module.stage_outbound_media_file

            def grow_then_stage(source, staging_root, **kwargs):
                source.write_bytes(b"12345")
                return real_stage(source, staging_root, **kwargs)

            with (
                unittest.mock.patch.object(self.adapter_module, "MAX_OUTBOUND_MEDIA_FILE_BYTES", 4),
                unittest.mock.patch.object(self.adapter_module, "MAX_OUTBOUND_MEDIA_BATCH_BYTES", 8),
                unittest.mock.patch.object(
                    self.adapter_module,
                    "stage_outbound_media_file",
                    side_effect=grow_then_stage,
                ),
                self.assertRaisesRegex(self.adapter_module.AgentControlError, "blob size limit"),
            ):
                await adapter.send_multiple_images("22" * 32, [(image.as_uri(), "caption")])

            client.send_media.assert_not_awaited()
            self.assertEqual(list(adapter._outbound_media_dir.iterdir()), [])

    async def test_multiple_images_partial_upload_failure_is_all_error_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.jpg"
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            class FakeClient:
                def __init__(self):
                    self.calls = 0
                    self.staged_paths = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.calls += 1
                    self.staged_paths = [Path(item["path"]) for item in attachments]
                    self.asserted_bytes = [path.read_bytes() for path in self.staged_paths]
                    raise self_error(
                        f"second upload failed at {self.staged_paths[1]}",
                        retryable=False,
                    )

            self_error = self.adapter_module.AgentControlError
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            with self.assertLogs(self.adapter_module.logger, level="DEBUG") as logs:
                with self.assertRaises(self.adapter_module.AgentControlError) as raised:
                    await adapter.send_multiple_images(
                        "22" * 32,
                        [(first.as_uri(), "caption"), (second.as_uri(), "")],
                    )

            self.assertEqual(str(raised.exception), "Marmot media send failed")
            self.assertNotIn(str(adapter._outbound_media_dir), str(raised.exception))
            self.assertNotIn(str(adapter._outbound_media_dir), "\n".join(logs.output))
            self.assertEqual(fake_client.calls, 1)
            self.assertEqual(fake_client.asserted_bytes, [b"one", b"two"])
            self.assertTrue(all(not path.exists() for path in fake_client.staged_paths))

    async def test_outbound_media_staging_failure_redacts_local_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "private.png"
            image.write_bytes(b"private")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=object(),
            )
            staged_path = adapter._outbound_media_dir / "private-staged.png"

            with (
                unittest.mock.patch.object(
                    self.adapter_module,
                    "stage_outbound_media_file",
                    side_effect=OSError(f"could not stage {staged_path}"),
                ),
                self.assertLogs(self.adapter_module.logger, level="DEBUG") as logs,
            ):
                result = await adapter.send_image_file("22" * 32, str(image))

            self.assertFalse(result.success)
            self.assertEqual(result.error, "Marmot outbound media staging failed")
            self.assertNotIn(str(staged_path), "\n".join(logs.output))

    async def test_multiple_images_retry_reuses_staged_paths_and_idempotency_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            class FakeClient:
                def __init__(self):
                    self.calls = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.calls.append(
                        ([item["path"] for item in attachments], kwargs["idempotency_key"])
                    )
                    if len(self.calls) == 1:
                        raise self_error(
                            "timed out",
                            code="request_timed_out",
                            retryable=True,
                        )
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            self_error = self.adapter_module.AgentControlError
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            with unittest.mock.patch.object(
                self.adapter_module,
                "SEND_MEDIA_RETRY_BACKOFF_S",
                (0.0,),
            ):
                await adapter.send_multiple_images(
                    "22" * 32,
                    [(first.as_uri(), "caption"), (second.as_uri(), "")],
                )

            self.assertEqual(len(fake_client.calls), 2)
            self.assertEqual(fake_client.calls[0], fake_client.calls[1])
            self.assertEqual(list(adapter._outbound_media_dir.iterdir()), [])

    async def test_multiple_images_waits_past_retry_budget_for_in_progress_send(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "image.png"
            image.write_bytes(b"image")

            class FakeClient:
                def __init__(self):
                    self.idempotency_keys = []

                async def send_media(self, account, group, attachments, **kwargs):
                    self.idempotency_keys.append(kwargs["idempotency_key"])
                    if len(self.idempotency_keys) <= 4:
                        raise self_error(
                            "send remains in progress",
                            code="send_in_progress",
                            retryable=True,
                        )
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            self_error = self.adapter_module.AgentControlError
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=fake_client,
            )
            with unittest.mock.patch.object(
                self.adapter_module,
                "SEND_MEDIA_RETRY_BACKOFF_S",
                (0.0,),
            ):
                await adapter.send_multiple_images(
                    "22" * 32,
                    [(image.as_uri(), "caption")],
                )

            self.assertEqual(len(fake_client.idempotency_keys), 5)
            self.assertEqual(len(set(fake_client.idempotency_keys)), 1)
            self.assertEqual(list(adapter._outbound_media_dir.iterdir()), [])

    async def test_multiple_images_cancellation_cleans_staged_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "cancel.png"
            image.write_bytes(b"cancel")
            entered = asyncio.Event()
            release = asyncio.Event()

            class FakeClient:
                async def send_media(self, account, group, attachments, **kwargs):
                    entered.set()
                    await release.wait()
                    return {"type": "final_sent", "message_ids_hex": ["99" * 32]}

            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=FakeClient(),
            )
            task = asyncio.create_task(
                adapter.send_multiple_images("22" * 32, [(image.as_uri(), "caption")])
            )
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            self.assertEqual(list(adapter._outbound_media_dir.iterdir()), [])

    async def test_multiple_images_reply_metadata_remains_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            image = root / "reply.png"
            image.write_bytes(b"reply")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "media_local_roots": [str(root)],
                    }
                ),
                client=object(),
            )
            with self.assertRaisesRegex(self.adapter_module.AgentControlError, "reply threading"):
                await adapter.send_multiple_images(
                    "22" * 32,
                    [(image.as_uri(), "caption")],
                    metadata={"reply_to_message_id_hex": "33" * 32},
                )

    async def test_standalone_media_files_use_one_batch_send(self):
        class FakeAdapter:
            def __init__(self):
                self.batches = []

            async def _send_media_batch(self, chat_id, attachments, *, caption=None, reply_to=None):
                self.batches.append((chat_id, attachments, caption, reply_to))
                return self_module.SendResult(
                    success=True,
                    message_id="99" * 32,
                    continuation_message_ids=("88" * 32,),
                    raw_response={
                        "attachment_outcomes": [
                            {"file_name": item["file_name"], "status": "sent"}
                            for item in attachments
                        ]
                    },
                )

        self_module = self.adapter_module
        fake_adapter = FakeAdapter()
        with unittest.mock.patch.object(
            self.adapter_module,
            "MarmotPlatformAdapter",
            return_value=fake_adapter,
        ):
            response = await self.adapter_module._standalone_send(
                object(),
                "22" * 32,
                " one caption ",
                media_files=["first.png", "second.jpg"],
            )
            blank_response = await self.adapter_module._standalone_send(
                object(),
                "22" * 32,
                "   ",
                media_files=["first.png"],
            )

        self.assertEqual(len(fake_adapter.batches), 2)
        batch = fake_adapter.batches[0]
        self.assertEqual(batch[0], "22" * 32)
        self.assertEqual([item["file_name"] for item in batch[1]], ["first.png", "second.jpg"])
        self.assertEqual(batch[2], " one caption ")
        self.assertEqual(response["message_ids"], ["88" * 32, "99" * 32])
        self.assertEqual(len(response["attachment_outcomes"]), 2)
        self.assertIsNone(fake_adapter.batches[1][2])
        self.assertTrue(blank_response["success"])

    async def test_outbound_media_outside_allowlist_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outside = Path(tmpdir) / "secret.png"
            outside.write_bytes(b"png")

            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "11" * 32, "home": tmpdir}),
                client=unittest.mock.AsyncMock(),
            )
            result = await adapter.send_image_file("22" * 32, str(outside), caption="look")
            self.assertFalse(result.success)
            self.assertIn("allowed local roots", result.error or "")

    async def test_outbound_media_reply_to_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            media_dir = Path(tmpdir) / "dev" / "inbound-media"
            media_dir.mkdir(parents=True)
            image_path = media_dir / "out.png"
            image_path.write_bytes(b"png")

            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "11" * 32, "home": tmpdir}),
                client=unittest.mock.AsyncMock(),
            )
            result = await adapter.send_image_file(
                "22" * 32,
                str(image_path),
                caption="look",
                reply_to="33" * 32,
            )
            self.assertFalse(result.success)
            self.assertIn("reply threading", result.error or "")


class DeleteMessageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_delete_message_uses_send_time_cache(self):
        class FakeClient:
            def __init__(self):
                self.deletes = []

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

            async def delete_message(self, account_id_hex, group_id_hex, target_message_id_hex):
                self.deletes.append((account_id_hex, group_id_hex, target_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": []}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )
        send_result = await adapter.send("22" * 32, "hello")
        self.assertTrue(send_result.success)

        deleted = await adapter.delete_message("", "88" * 32)
        self.assertTrue(deleted)
        self.assertEqual(
            fake_client.deletes,
            [("11" * 32, "22" * 32, "88" * 32)],
        )


class GroupActivationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_unaddressed_multi_party_message_is_skipped(self):
        class FakeClient:
            async def group_info(self, account_id_hex, group_id_hex):
                return {"type": "group_info", "is_direct": False, "member_count": 3}

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32, "group_activation": "mention"}),
            client=FakeClient(),
        )
        adapter.handle_message = unittest.mock.AsyncMock()

        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message_id_hex": "33" * 32,
            "sender_account_id_hex": "44" * 32,
            "text": "hello everyone",
            "mentions_self": False,
        }
        await adapter._dispatch_inbound_message(event)
        adapter.handle_message.assert_not_called()

    async def test_mention_pattern_triggers_turn(self):
        class FakeClient:
            async def group_info(self, account_id_hex, group_id_hex):
                raise AssertionError("group_info should not run when mention pattern matches")

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "group_activation": "mention",
                    "mention_patterns": ["marvin"],
                }
            ),
            client=FakeClient(),
        )
        adapter.handle_message = unittest.mock.AsyncMock()

        event = {
            "type": "inbound_message",
            "account_id_hex": "11" * 32,
            "group_id_hex": "22" * 32,
            "message_id_hex": "33" * 32,
            "sender_account_id_hex": "44" * 32,
            "text": "hey marvin, status?",
            "mentions_self": False,
        }
        await adapter._dispatch_inbound_message(event)
        adapter.handle_message.assert_called_once()


class ConfigResolutionTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()

    def test_resolve_group_activation_and_mention_patterns(self):
        extra = {
            "group_activation": "always",
            "mention_patterns": ["bot", "assistant"],
            "agent_name": "Marvin",
        }
        self.assertEqual(self.adapter_module.resolve_group_activation(extra), "always")
        self.assertEqual(
            self.adapter_module.resolve_mention_patterns(extra),
            ["bot", "assistant", "Marvin"],
        )


class CoalesceInboundTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()

    def test_coalesce_dedupes_media_and_keeps_newest_reply_to(self):
        ref = {
            "file_name": "a.png",
            "media_type": "image/png",
            "ciphertext_sha256": "aa" * 32,
            "plaintext_sha256": "bb" * 32,
            "nonce_hex": "cc",
            "version": "1",
            "source_epoch": 1,
            "locators": [],
        }
        merged = self.adapter_module._coalesce_inbound_events(
            [
                {
                    "type": "inbound_message",
                    "message_id_hex": "11" * 32,
                    "reply_to_message_id_hex": "aa" * 32,
                    "text": "one",
                    "media": [ref],
                },
                {
                    "type": "inbound_message",
                    "message_id_hex": "22" * 32,
                    "reply_to": {
                        "message_id_hex": "bb" * 32,
                        "availability": "available",
                        "sender": {
                            "account_id_hex": "44" * 32,
                            "display_name": "Alice",
                            "is_self": False,
                        },
                        "recorded_at": 123,
                        "text_excerpt": "rich quoted context",
                        "text_truncated": False,
                        "attachments": [],
                        "attachments_truncated": False,
                    },
                    "text": "two",
                    "media": [dict(ref)],
                },
            ]
        )
        self.assertEqual(merged["message_id_hex"], "22" * 32)
        self.assertEqual(merged["reply_to_message_id_hex"], "bb" * 32)
        self.assertEqual(
            merged["reply_to"]["text_excerpt"],
            "rich quoted context",
        )
        self.assertEqual(merged["text"], "one\ntwo")
        self.assertEqual(len(merged["media"]), 1)

    def test_normalization_rejects_missing_routing_ids_consistently(self):
        with self.assertRaises(self.adapter_module.AgentControlError) as raised:
            self.adapter_module._normalize_inbound_message_event(
                {
                    "type": "inbound_message",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "",
                    "message": {
                        "message_id_hex": "22" * 32,
                        "sender": {
                            "account_id_hex": "44" * 32,
                            "is_self": False,
                        },
                        "text": "hello",
                        "recorded_at": 1,
                        "media": [],
                    },
                    "mentions_self": False,
                }
            )
        self.assertEqual(raised.exception.code, "wrong_protocol")


class WelcomerAllowlistTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()

    async def test_sync_allowlist_adds_and_removes(self):
        current = ["33" * 32, "44" * 32]

        class FakeClient:
            async def allowlist_list(self, account_id_hex):
                return {"type": "allowlist", "welcomer_account_ids_hex": list(current)}

            async def allowlist_add(self, account_id_hex, welcomer_account_id_hex):
                current.append(welcomer_account_id_hex)

            async def allowlist_remove(self, account_id_hex, welcomer_account_id_hex):
                current.remove(welcomer_account_id_hex)

        result = await self.adapter_module.sync_allowlist(
            FakeClient(),
            "11" * 32,
            ["22" * 32, "33" * 32],
        )
        self.assertEqual(result["added"], ["22" * 32])
        self.assertEqual(result["removed"], ["44" * 32])
        self.assertEqual(sorted(current), sorted(["22" * 32, "33" * 32]))

    async def test_sync_allowlist_decodes_npub(self):
        current = []

        class FakeClient:
            async def allowlist_list(self, account_id_hex):
                return {"type": "allowlist", "welcomer_account_ids_hex": list(current)}

            async def allowlist_add(self, account_id_hex, welcomer_account_id_hex):
                current.append(welcomer_account_id_hex)

            async def allowlist_remove(self, account_id_hex, welcomer_account_id_hex):
                current.remove(welcomer_account_id_hex)

        result = await self.adapter_module.sync_allowlist(
            FakeClient(),
            "11" * 32,
            ["npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"],
        )
        expected = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"
        self.assertEqual(result, {"added": [expected], "removed": []})
        self.assertEqual(current, [expected])

    async def test_sync_allowlist_does_not_wipe_on_invalid_nonempty_config(self):
        current = ["33" * 32]

        class FakeClient:
            async def allowlist_list(self, account_id_hex):
                return {"type": "allowlist", "welcomer_account_ids_hex": list(current)}

            async def allowlist_add(self, account_id_hex, welcomer_account_id_hex):
                current.append(welcomer_account_id_hex)

            async def allowlist_remove(self, account_id_hex, welcomer_account_id_hex):
                current.remove(welcomer_account_id_hex)

        result = await self.adapter_module.sync_allowlist(
            FakeClient(), "11" * 32, ["npub1invalid"]
        )
        self.assertEqual(result, {"added": [], "removed": []})
        self.assertEqual(current, ["33" * 32])


class GroupInviteOnboardingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_group_invite_sends_profile_prompt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "profile-onboarding.json"

            class FakeClient:
                async def account_lookup_profile(self, account_id_hex):
                    return {"type": "profile_lookup", "status": "profile_not_found", "retryable": False}

                async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None, idempotency_key=None):
                    self.last = (account_id_hex, group_id_hex, text, reply_to_message_id_hex)
                    return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                        "agent_name": "Marvin",
                    }
                ),
                client=fake_client,
            )
            await adapter._handle_group_invite(
                {
                    "type": "group_invite",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                }
            )
            await adapter._inbound_queue.join()

            self.assertIn("Marvin", fake_client.last[2])
            self.assertIsNone(fake_client.last[3])


class ProfilePromptTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()

    def test_build_profile_prompt_offers_configured_name(self):
        prompt = self.adapter_module.build_profile_prompt("Marvin")
        self.assertIn("Marvin", prompt)
        self.assertIn("yes", prompt.casefold())

    def test_parse_profile_name_reply_accepts_affirm(self):
        action, name, _ = self.adapter_module.parse_profile_name_reply("yes")
        self.assertEqual(action, "affirm")
        self.assertIsNone(name)


class PluginRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()

    def test_register_exposes_marmot_history_as_a_platform_tool(self):
        class FakeContext:
            def __init__(self):
                self.platforms = []
                self.tools = []

            def register_platform(self, **kwargs):
                self.platforms.append(kwargs)

            def register_tool(self, **kwargs):
                self.tools.append(kwargs)

        ctx = FakeContext()
        self.adapter_module.register(ctx)

        self.assertEqual([platform["name"] for platform in ctx.platforms], ["marmot"])
        history = next(tool for tool in ctx.tools if tool["name"] == "marmot_history")
        self.assertEqual(history["toolset"], "platform")
        self.assertEqual(history["schema"]["required"], ["group_id_hex"])
        self.assertIs(history["handler"], self.adapter_module._marmot_history_tool)

    def test_marmot_history_fetches_one_exact_materialized_message(self):
        calls = []

        class FakeClient:
            async def timeline_message_get(
                self, account_id_hex, group_id_hex, message_id_hex
            ):
                calls.append((account_id_hex, group_id_hex, message_id_hex))
                return {
                    "type": "timeline_message",
                    "message_id_hex": message_id_hex,
                    "message": None,
                }

        class FakeAdapter:
            client = FakeClient()

            async def _ensure_account_id(self):
                return "11" * 32

        class AdapterMap:
            def get(self, _platform):
                return FakeAdapter()

        gateway_run = types.ModuleType("gateway.run")
        gateway_run._gateway_runner_ref = lambda: types.SimpleNamespace(
            adapters=AdapterMap()
        )
        model_tools = types.ModuleType("model_tools")
        model_tools._run_async = asyncio.run
        sys.modules["gateway.run"] = gateway_run
        sys.modules["model_tools"] = model_tools

        try:
            result = json.loads(
                self.adapter_module._marmot_history_tool(
                    {
                        "group_id_hex": "22" * 32,
                        "message_id_hex": "33" * 32,
                    }
                )
            )
        finally:
            sys.modules.pop("gateway.run", None)
            sys.modules.pop("model_tools", None)

        self.assertTrue(result["ok"])
        self.assertEqual(result["type"], "timeline_message")
        self.assertEqual(calls, [("11" * 32, "22" * 32, "33" * 32)])


class KeyedAsyncQueueDepthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()

    async def test_queue_sheds_incoming_turn_at_depth_cap(self):
        queue = self.adapter_module.KeyedAsyncQueue(max_depth_per_key=2)
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocking_turn():
            started.set()
            await release.wait()

        queue.enqueue("group-a", blocking_turn)
        await asyncio.wait_for(started.wait(), timeout=1)
        queue.enqueue("group-a", lambda: asyncio.sleep(0))
        shed = queue.enqueue("group-a", lambda: asyncio.sleep(0))
        self.assertIsNone(shed)

        release.set()
        await queue.join()


if __name__ == "__main__":
    unittest.main()
