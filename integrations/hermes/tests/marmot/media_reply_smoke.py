"""Drive Hermes media replies against the Rust connector/receiver fixture."""

import asyncio
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import traceback


SMOKE_TIMEOUT_S = 60.0
IO_TIMEOUT_S = 30.0


class LostResponseProxy:
    def __init__(self, upstream, bounded_wait, frame_limit):
        self.upstream = upstream
        self.bounded_wait = bounded_wait
        self.frame_limit = frame_limit
        self.server = None
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.sends = 0
        self.drops = 0

    async def start(self, path):
        self.server = await self.bounded_wait(
            asyncio.start_unix_server(self.accept, path=str(path), limit=self.frame_limit + 1),
            timeout=IO_TIMEOUT_S,
        )

    def accept(self, reader, writer):
        self.writers.add(writer)
        task = asyncio.create_task(self.forward(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def close_writer(self, writer):
        writer.close()
        try:
            await self.bounded_wait(writer.wait_closed(), timeout=1.0)
        except (TimeoutError, OSError) as exc:
            writer.transport.abort()
            self.errors.append(exc)
        finally:
            self.writers.discard(writer)

    async def forward(self, reader, writer):
        upstream_writer = None
        try:
            request = await self.bounded_wait(reader.readuntil(b"\n"), timeout=IO_TIMEOUT_S)
            upstream_reader, upstream_writer = await self.bounded_wait(
                asyncio.open_unix_connection(self.upstream, limit=self.frame_limit + 1),
                timeout=IO_TIMEOUT_S,
            )
            self.writers.add(upstream_writer)
            upstream_writer.write(request)
            await self.bounded_wait(upstream_writer.drain(), timeout=IO_TIMEOUT_S)
            self.sends += 1
            drop_response = self.sends == 1
            response = await self.bounded_wait(
                upstream_reader.readuntil(b"\n"), timeout=IO_TIMEOUT_S
            )
            if drop_response:
                self.drops += 1
            else:
                writer.write(response)
                await self.bounded_wait(writer.drain(), timeout=IO_TIMEOUT_S)
        except Exception as exc:
            self.errors.append(exc)
        finally:
            if upstream_writer is not None:
                await self.close_writer(upstream_writer)
            await self.close_writer(writer)

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.bounded_wait(self.server.wait_closed(), timeout=2.0)
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        for writer in tuple(self.writers):
            writer.close()
        if tasks:
            results = await self.bounded_wait(
                asyncio.gather(*tasks, return_exceptions=True), timeout=3.0
            )
            self.errors.extend(
                result for result in results
                if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError)
            )
        if self.errors:
            raise RuntimeError("control proxy or cleanup failed") from self.errors[0]


async def smoke(module, socket_path, account_id, group_id, target_id, home):
    control = sys.modules["marmot_hermes.agent_control"]

    class RecordingClient(control.MarmotAgentControlClient):
        def __init__(self, path):
            super().__init__(path)
            self.message_ids = []

        async def send_media(self, *args, **kwargs):
            response = await super().send_media(*args, **kwargs)
            ids = response.get("message_ids_hex")
            if not isinstance(ids, list) or len(ids) != 1:
                raise AssertionError("expected one real message ID per media batch")
            self.message_ids.append(ids[0])
            return response

    home = Path(home).resolve(strict=True)
    inbound = home / "dev" / "inbound-media"
    inbound.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = [inbound / f"python-{index}.txt" for index in range(4)]
    for index, path in enumerate(paths):
        with path.open("xb") as fixture:
            fixture.write(f"python attachment {index}".encode())

    with tempfile.TemporaryDirectory(prefix="mp", dir=home) as proxy_home:
        proxy_path = Path(proxy_home) / "s"
        proxy = LostResponseProxy(socket_path, control.bounded_wait, control.MAX_FRAME_BYTES)
        adapter = None
        try:
            await proxy.start(proxy_path)
            client = RecordingClient(proxy_path)
            config = sys.modules["gateway.config"].PlatformConfig(extra={
                "socket_path": str(proxy_path),
                "account_id_hex": account_id,
                "home": str(home),
                "media_local_roots": [str(inbound)],
                "profile_name_onboarding": False,
            })
            adapter = module.MarmotPlatformAdapter(config, client=client)
            calls = (
                (adapter.send_image_file, paths[0], "python send_image_file",
                 {"reply_to": target_id.upper()}),
                (adapter.send_document, paths[1], "python send_document",
                 {"metadata": {"reply_to_message_id_hex": target_id}}),
                (adapter.send_video, paths[2], "python send_video",
                 {"metadata": {"delivery_context": {"reply_to_message_id": target_id}}}),
                (adapter.send_voice, paths[3], "python send_voice",
                 {"metadata": {"parent_message_id_hex": target_id}}),
            )
            for method, path, caption, kwargs in calls:
                result = await method(group_id, str(path), caption=caption, **kwargs)
                if not result.success:
                    raise AssertionError(f"{method.__name__} failed: {result.error}")
                if proxy.errors:
                    raise RuntimeError("control proxy failed") from proxy.errors[0]

            await adapter.send_multiple_images(
                group_id,
                [(paths[0].as_uri(), "python multi"), (paths[1].as_uri(), "")],
                metadata={"reply_to": {"message_id_hex": target_id, "availability": "missing"}},
            )
            if proxy.errors:
                raise RuntimeError("control proxy failed") from proxy.errors[0]
            if proxy.sends != 6 or proxy.drops != 1:
                raise AssertionError(
                    f"expected six upstream sends and one dropped response, got {proxy.sends}/{proxy.drops}"
                )
            if len(client.message_ids) != 5:
                raise AssertionError("expected five successful real media responses")
            return {"message_ids_hex": client.message_ids, "dropped_response": True}
        finally:
            try:
                if adapter is not None:
                    await control.bounded_wait(adapter.disconnect(), timeout=5.0)
            finally:
                await proxy.close()


def main():
    if len(sys.argv) != 6:
        raise ValueError("usage: media_reply_smoke.py SOCKET ACCOUNT_ID_HEX GROUP_ID_HEX TARGET_MESSAGE_ID_HEX HOME")
    os.umask(0o077)
    for key in tuple(os.environ):
        if key.startswith("MARMOT_") or key in {"HERMES_HOME", "PYTHONPATH"}:
            del os.environ[key]
    os.environ["HERMES_HOME"] = str(Path(sys.argv[5]).resolve(strict=True))
    from test_adapter import load_adapter_module

    module = load_adapter_module(media_kinds=True)
    result = asyncio.run(module.bounded_wait(smoke(module, *sys.argv[1:]), timeout=SMOKE_TIMEOUT_S))
    print(json.dumps(result))


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    try:
        main()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
