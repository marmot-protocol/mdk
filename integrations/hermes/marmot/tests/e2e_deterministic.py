#!/usr/bin/env python3
"""Deterministic Hermes/Marmot adapter E2E harness.

This test uses a real Hermes checkout and the real Marmot Hermes plugin, but it
replaces both sides that would otherwise require a full Marmot account and an
LLM:

* a fake ``dm-agent`` Unix socket speaks the agent-control protocol;
* a deterministic Hermes message handler returns a fixed response string.

That still exercises Hermes' BasePlatformAdapter intake/delivery pipeline and
the Marmot plugin's inbound subscription plus durable ``send_final`` path.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any

ACCOUNT_ID_HEX = "11" * 32
GROUP_ID_HEX = "22" * 32
MESSAGE_ID_HEX = "33" * 32
SENDER_ACCOUNT_ID_HEX = "44" * 32
INBOUND_TEXT = "ping from marmot"
DETERMINISTIC_RESPONSE = f"marmot-e2e-ok: {INBOUND_TEXT}"
PROTOCOL = "marmot.agent-control.v1"


async def read_json_line(reader: asyncio.StreamReader) -> dict[str, Any]:
    raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
    if not raw:
        raise RuntimeError("agent-control client closed before sending a request")
    return json.loads(raw.decode("utf-8"))


async def write_json_line(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    writer.write(json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n")
    await writer.drain()


class FakeAgentControlServer:
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path
        self.server: asyncio.AbstractServer | None = None
        self.subscribed = asyncio.Event()
        self.release_inbound = asyncio.Event()
        self.final_sent = asyncio.Event()
        self.sent_final_request: dict[str, Any] | None = None
        self.requests: list[dict[str, Any]] = []

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

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await read_json_line(reader)
            self.requests.append(request)
            if request.get("marmot_agent_control") != PROTOCOL:
                raise RuntimeError(f"wrong protocol: {request.get('marmot_agent_control')!r}")

            request_type = request.get("type")
            if request_type == "subscribe_inbound":
                await self._handle_subscribe(request, writer)
                return
            if request_type == "send_final":
                await self._handle_send_final(request, writer)
                return

            await write_json_line(
                writer,
                {
                    "marmot_agent_control": PROTOCOL,
                    "id": request["id"],
                    "type": "error",
                    "code": "unexpected_request",
                    "message": f"unexpected request type: {request_type}",
                },
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_subscribe(
        self,
        request: dict[str, Any],
        writer: asyncio.StreamWriter,
    ) -> None:
        assert request.get("account_id_hex") == ACCOUNT_ID_HEX
        assert request.get("group_id_hex") in (None, GROUP_ID_HEX)
        await write_json_line(
            writer,
            {
                "marmot_agent_control": PROTOCOL,
                "id": request["id"],
                "type": "ack",
            },
        )
        self.subscribed.set()
        await asyncio.wait_for(self.release_inbound.wait(), timeout=5.0)
        await write_json_line(
            writer,
            {
                "marmot_agent_control": PROTOCOL,
                "id": request["id"],
                "type": "inbound_message",
                "account_id_hex": ACCOUNT_ID_HEX,
                "group_id_hex": GROUP_ID_HEX,
                "message_id_hex": MESSAGE_ID_HEX,
                "sender_account_id_hex": SENDER_ACCOUNT_ID_HEX,
                "text": INBOUND_TEXT,
            },
        )
        await asyncio.wait_for(self.final_sent.wait(), timeout=5.0)

    async def _handle_send_final(
        self,
        request: dict[str, Any],
        writer: asyncio.StreamWriter,
    ) -> None:
        self.sent_final_request = request
        await write_json_line(
            writer,
            {
                "marmot_agent_control": PROTOCOL,
                "id": request["id"],
                "type": "final_sent",
                "message_ids_hex": ["55" * 32],
            },
        )
        self.final_sent.set()


def load_marmot_adapter_module(plugin_path: Path):
    spec = importlib.util.spec_from_file_location("marmot_hermes_adapter_e2e", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load plugin adapter: {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def run() -> None:
    plugin_path = Path(os.environ.get("HERMES_HOME", "")) / "plugins" / "marmot" / "adapter.py"
    if not plugin_path.exists():
        raise SystemExit(f"plugin adapter not found: {plugin_path}")

    module = load_marmot_adapter_module(plugin_path)

    from gateway.config import PlatformConfig
    from gateway.platform_registry import PlatformEntry, platform_registry

    if not platform_registry.is_registered("marmot"):
        platform_registry.register(
            PlatformEntry(
                name="marmot",
                label="Marmot",
                adapter_factory=lambda cfg: module.MarmotPlatformAdapter(cfg),
                check_fn=lambda: True,
                validate_config=lambda cfg: True,
                source="plugin",
                plugin_name="marmot",
            )
        )

    with tempfile.TemporaryDirectory(prefix="marmot-hermes-e2e-") as tmp:
        fake_server = FakeAgentControlServer(Path(tmp) / "dm-agent.sock")
        await fake_server.start()
        prior_socket = os.environ.get("MARMOT_AGENT_SOCKET")
        os.environ["MARMOT_AGENT_SOCKET"] = str(fake_server.socket_path)
        try:
            config = PlatformConfig(
                enabled=True,
                extra={
                    "socket_path": str(fake_server.socket_path),
                    "account_id_hex": ACCOUNT_ID_HEX,
                    "group_id_hex": GROUP_ID_HEX,
                },
            )
            adapter = module.MarmotPlatformAdapter(config)

            async def deterministic_handler(event):
                assert event.text == INBOUND_TEXT
                assert event.message_id == MESSAGE_ID_HEX
                assert event.source.chat_id == GROUP_ID_HEX
                assert event.source.user_id == SENDER_ACCOUNT_ID_HEX
                return DETERMINISTIC_RESPONSE

            adapter.set_message_handler(deterministic_handler)
            connected = await adapter.connect()
            if not connected:
                raise RuntimeError("adapter failed to connect")

            await asyncio.wait_for(fake_server.subscribed.wait(), timeout=5.0)
            fake_server.release_inbound.set()
            await asyncio.wait_for(fake_server.final_sent.wait(), timeout=5.0)
            await adapter.disconnect()
        finally:
            if prior_socket is None:
                os.environ.pop("MARMOT_AGENT_SOCKET", None)
            else:
                os.environ["MARMOT_AGENT_SOCKET"] = prior_socket
            await fake_server.close()

    sent = fake_server.sent_final_request
    if sent is None:
        raise AssertionError("Marmot adapter did not send a durable final response")
    assert sent["type"] == "send_final"
    assert sent["account_id_hex"] == ACCOUNT_ID_HEX
    assert sent["group_id_hex"] == GROUP_ID_HEX
    assert sent["reply_to_message_id_hex"] == MESSAGE_ID_HEX
    assert sent["text"] == DETERMINISTIC_RESPONSE

    print("deterministic Hermes/Marmot E2E passed")
    print(f"request_count: {len(fake_server.requests)}")
    print(f"final_text: {sent['text']}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
