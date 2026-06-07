#!/usr/bin/env python3
"""Deterministic Hermes/Marmot E2E using a real ``dm-agent`` process.

This harness keeps the agent response deterministic and model-free, but replaces
the fake agent-control socket from ``e2e_deterministic.py`` with the real
connector daemon. ``dm-agent`` runs with explicit debug controls enabled so the
test can inject one inbound message and inspect the final send without creating
real Marmot accounts, groups, relays, or an LLM provider.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

ACCOUNT_ID_HEX = "11" * 32
GROUP_ID_HEX = "22" * 32
MESSAGE_ID_HEX = "33" * 32
SENDER_ACCOUNT_ID_HEX = "44" * 32
INBOUND_TEXT = "ping from connector"
DETERMINISTIC_RESPONSE = f"marmot-e2e-ok: {INBOUND_TEXT}"
PROTOCOL = "marmot.agent-control.v1"
CONNECTOR_START_TIMEOUT_SECONDS = float(os.environ.get("MARMOT_CONNECTOR_E2E_START_TIMEOUT", "120"))


def load_marmot_adapter_module(plugin_path: Path):
    spec = importlib.util.spec_from_file_location("marmot_hermes_connector_e2e", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load plugin adapter: {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def register_marmot_platform(module) -> None:
    from gateway.platform_registry import PlatformEntry, platform_registry

    if platform_registry.is_registered("marmot"):
        return
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


async def read_stream_tail(stream: asyncio.StreamReader | None) -> str:
    if stream is None:
        return ""
    try:
        data = await asyncio.wait_for(stream.read(), timeout=1.0)
    except asyncio.TimeoutError:
        return ""
    return data.decode("utf-8", errors="replace")


async def wait_for_connector(socket_path: Path, client, proc: asyncio.subprocess.Process) -> None:
    deadline = asyncio.get_running_loop().time() + CONNECTOR_START_TIMEOUT_SECONDS
    while asyncio.get_running_loop().time() < deadline:
        if proc.returncode is not None:
            stderr = await read_stream_tail(proc.stderr)
            raise RuntimeError(f"dm-agent exited before socket was ready:\n{stderr}")
        try:
            await client.request({"type": "debug_recorded_finals"}, request_id=uuid.uuid4().hex)
            return
        except Exception:
            await asyncio.sleep(0.1)
    raise RuntimeError(
        f"dm-agent socket did not become ready within "
        f"{CONNECTOR_START_TIMEOUT_SECONDS:.0f}s: {socket_path}"
    )


async def stop_process(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def inject_until_final(client) -> list[dict[str, Any]]:
    inject_payload = {
        "type": "debug_inject_inbound",
        "account_id_hex": ACCOUNT_ID_HEX,
        "group_id_hex": GROUP_ID_HEX,
        "message_id_hex": MESSAGE_ID_HEX,
        "sender_account_id_hex": SENDER_ACCOUNT_ID_HEX,
        "text": INBOUND_TEXT,
    }
    for _ in range(30):
        await client.request(inject_payload, request_id=uuid.uuid4().hex)
        for _ in range(10):
            recorded = await client.request({"type": "debug_recorded_finals"}, request_id=uuid.uuid4().hex)
            sends = list(recorded.get("sends") or [])
            if sends:
                return sends
            await asyncio.sleep(0.1)
    raise AssertionError("Hermes did not produce a recorded final send through dm-agent")


async def run() -> None:
    darkmatter_repo = Path(os.environ["DARKMATTER_REPO"])
    plugin_path = Path(os.environ.get("HERMES_HOME", "")) / "plugins" / "marmot" / "adapter.py"
    if not plugin_path.exists():
        raise SystemExit(f"plugin adapter not found: {plugin_path}")

    module = load_marmot_adapter_module(plugin_path)
    register_marmot_platform(module)

    from gateway.config import PlatformConfig

    with tempfile.TemporaryDirectory(prefix="marmot-hermes-connector-e2e-") as tmp:
        tmp_path = Path(tmp)
        marmot_home = tmp_path / "marmot-home"
        socket_path = tmp_path / "dm-agent.sock"
        proc = await asyncio.create_subprocess_exec(
            "cargo",
            "run",
            "-q",
            "-p",
            "agent-connector",
            "--bin",
            "dm-agent",
            "--",
            "--home",
            str(marmot_home),
            "--socket",
            str(socket_path),
            "--debug-controls",
            cwd=str(darkmatter_repo),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        prior_socket = os.environ.get("MARMOT_AGENT_SOCKET")
        os.environ["MARMOT_AGENT_SOCKET"] = str(socket_path)
        adapter = None
        try:
            client = module.MarmotAgentControlClient(socket_path, request_timeout=5.0)
            await wait_for_connector(socket_path, client, proc)

            config = PlatformConfig(
                enabled=True,
                extra={
                    "socket_path": str(socket_path),
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

            sends = await inject_until_final(client)
            send = sends[0]
            assert send["account_id_hex"] == ACCOUNT_ID_HEX
            assert send["group_id_hex"] == GROUP_ID_HEX
            assert send["reply_to_message_id_hex"] == MESSAGE_ID_HEX
            assert send["text"] == DETERMINISTIC_RESPONSE
            assert send["message_ids_hex"] == [f"{1:064x}"]
        finally:
            if adapter is not None:
                await adapter.disconnect()
            if prior_socket is None:
                os.environ.pop("MARMOT_AGENT_SOCKET", None)
            else:
                os.environ["MARMOT_AGENT_SOCKET"] = prior_socket
            await stop_process(proc)

    print("deterministic Hermes/Marmot connector E2E passed")
    print(f"socket: {socket_path}")
    print(f"final_text: {DETERMINISTIC_RESPONSE}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
