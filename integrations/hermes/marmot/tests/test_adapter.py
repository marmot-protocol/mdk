import asyncio
from contextlib import suppress
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

    async def test_auth_token_is_written_when_configured(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
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

    async def test_account_publish_profile_writes_public_profile_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
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
                    "marmot_agent_control": "marmot.agent-control.v1",
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

    async def test_inbound_subscription_waits_without_request_timeout_after_ack(self):
        release_event = asyncio.Event()

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
            await release_event.wait()
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
                    "text": "after idle",
                },
            )
            await writer.drain()
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)
        events = client.inbound_events(account_id_hex="11" * 32)

        pending_event = asyncio.create_task(anext(events))
        try:
            await asyncio.sleep(0.05)
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

    async def test_adapter_reads_auth_token_file_for_control_client(self):
        with tempfile.TemporaryDirectory() as tempdir:
            token_file = Path(tempdir) / "control.token"
            token_file.write_text("file-token\n", encoding="utf-8")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "socket_path": str(Path(tempdir) / "dm-agent.sock"),
                        "auth_token_file": str(token_file),
                    }
                )
            )

        self.assertEqual(adapter.client.auth_token, "file-token")

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

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
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

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
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
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
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

    async def test_first_inbound_message_prompts_for_public_profile_name(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hello",
            }
        ]

        class FakeClient:
            def __init__(self):
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
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

            await adapter._consume_inbound_once()

        self.assertEqual(adapter.events, [])
        self.assertEqual(len(fake_client.final_sends), 1)
        account_id, group_id, text, reply_to = fake_client.final_sends[0]
        self.assertEqual(account_id, "11" * 32)
        self.assertEqual(group_id, "22" * 32)
        self.assertIn("public Nostr profile name", text)
        self.assertEqual(reply_to, "33" * 32)

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
            }
        ]

        class FakeClient:
            def __init__(self):
                self.published_profiles = []
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

            async def account_publish_profile(self, account_id_hex, name, display_name=None):
                self.published_profiles.append((account_id_hex, name, display_name))
                return {
                    "type": "profile_published",
                    "account_id_hex": account_id_hex,
                    "name": name,
                    "display_name": display_name,
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
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

            await adapter._consume_inbound_once()

        self.assertEqual(adapter.events, [])
        self.assertEqual(fake_client.published_profiles, [(account_id, "Hermes Agent", "Hermes Agent")])
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertIn('published this agent', fake_client.final_sends[0][2])
        self.assertEqual(fake_client.final_sends[0][3], "33" * 32)

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
        self.assertEqual(final.message_id, "77" * 32)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "hel"), ("55" * 32, "lo")],
        )
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.stream_finalizes[0][1], "hello")
        self.assertEqual(fake_client.stream_finalizes[0][3], 2)
        self.assertEqual(fake_client.final_sends, [])

    async def test_draft_stream_skips_empty_visible_frames(self):
        class FakeClient:
            def __init__(self):
                self.stream_begins = []
                self.stream_appends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.stream_begins.append((account_id_hex, group_id_hex, tuple(quic_candidates)))
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
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

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
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

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
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

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
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

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
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

    async def test_whitespace_mismatched_final_replaces_preview_without_duplication(self):
        class FakeClient:
            def __init__(self):
                self.stream_finalizes = []
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
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

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
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
                return {"type": "stream_finalized", "stream_id_hex": stream_id_hex}

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

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


if __name__ == "__main__":
    unittest.main()
