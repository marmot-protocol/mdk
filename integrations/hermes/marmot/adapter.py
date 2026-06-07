"""Hermes platform plugin for the local Marmot agent connector.

The adapter is intentionally thin: Hermes owns agent execution and tools, while
``dm-agent`` owns Marmot account state, MLS group state, durable sends, and QUIC
preview streams.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

logger = logging.getLogger(__name__)

PROTOCOL = "marmot.agent-control.v1"
MAX_FRAME_BYTES = 1024 * 1024
DEFAULT_SOCKET_HOME = "~/.marmot"
DEFAULT_STREAM_CHUNK_BYTES = 1024
TEXT_DELTA_RECORD = 0x01
STATUS_RECORD = 0x03
TRANSCRIPT_HASH_CONTEXT = b"marmot agent text stream transcript v1"
STREAM_MESSAGE_PREFIX = "marmot-stream:"
DEFAULT_STREAMING_CURSOR = "\u2589"


class AgentControlError(RuntimeError):
    """Raised when the local ``dm-agent`` control socket rejects a request."""

    def __init__(self, message: str, *, code: str = "agent_control_error", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class NonAppendOnlyUpdate(RuntimeError):
    """Raised when a gateway replacement cannot be represented as an append."""


class AppendOnlyTextState:
    """Tracks the latest visible stream text and returns safe suffix deltas."""

    def __init__(self):
        self.text = ""

    def suffix_for(self, next_text: str) -> str:
        next_text = str(next_text or "")
        if not next_text.startswith(self.text):
            raise NonAppendOnlyUpdate("Marmot stream update is not append-only")
        suffix = next_text[len(self.text):]
        self.text = next_text
        return suffix


class AgentTextStreamTranscript:
    """Python mirror of ``AgentTextStreamTranscriptV1`` in ``cgka_traits``."""

    def __init__(self, stream_id_hex: str, start_message_id_hex: str, *, chunk_bytes: int):
        self.stream_id = bytes.fromhex(_normalize_hex(stream_id_hex, "stream_id_hex"))
        self.start_message_id = bytes.fromhex(_normalize_hex(start_message_id_hex, "start_message_id_hex"))
        self.chunk_bytes = int(chunk_bytes)
        self.next_seq = 1
        self.chunk_count = 0

        hasher = hashlib.sha256()
        hasher.update(TRANSCRIPT_HASH_CONTEXT)
        _hash_len_prefixed(hasher, self.stream_id)
        _hash_len_prefixed(hasher, self.start_message_id)
        self._hash = hasher.digest()

    @property
    def hash_hex(self) -> str:
        return self._hash.hex()

    def append_text(self, text: str) -> None:
        self._append_record(TEXT_DELTA_RECORD, text)

    def append_status(self, status: str) -> None:
        self._append_record(STATUS_RECORD, status)

    def _append_record(self, record_type: int, text: str) -> None:
        for chunk in split_text_deltas(text, self.chunk_bytes):
            hasher = hashlib.sha256()
            hasher.update(self._hash)
            hasher.update(self.next_seq.to_bytes(8, "big"))
            hasher.update(bytes([record_type]))
            hasher.update(chunk)
            self._hash = hasher.digest()
            self.next_seq += 1
            self.chunk_count += 1


class MarmotAgentControlClient:
    """Small NDJSON client for ``crates/agent-control``."""

    def __init__(self, socket_path: str | Path, *, request_timeout: float = 30.0):
        self.socket_path = str(Path(socket_path).expanduser())
        self.request_timeout = float(request_timeout)

    async def request(self, payload: Dict[str, Any], *, request_id: Optional[str] = None) -> Dict[str, Any]:
        request_id = request_id or uuid.uuid4().hex
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._write_envelope(writer, payload, request_id=request_id)
            response = await self._read_envelope(reader)
            self._validate_response_id(response, request_id)
            self._raise_if_error(response)
            return response
        except OSError as exc:
            raise AgentControlError(str(exc), code="socket_io", retryable=True) from exc
        finally:
            await _close_writer(writer)

    async def account_list(self) -> Dict[str, Any]:
        return await self.request({"type": "account_list"})

    async def send_final(
        self,
        account_id_hex: str,
        group_id_hex: str,
        text: str,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "send_final",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "text": str(text or ""),
                "reply_to_message_id_hex": reply_to_message_id_hex,
            }
        )

    async def stream_begin(
        self,
        account_id_hex: str,
        group_id_hex: str,
        *,
        stream_id_hex: Optional[str] = None,
        quic_candidates: Iterable[str] = (),
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_begin",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex") if stream_id_hex else None,
                "quic_candidates": [str(candidate).strip() for candidate in quic_candidates if str(candidate).strip()],
            }
        )

    async def stream_append(self, stream_id_hex: str, append_text: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_append",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "append_text": str(append_text or ""),
            }
        )

    async def stream_status(self, stream_id_hex: str, status: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_status",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "status": str(status or ""),
            }
        )

    async def stream_finalize(
        self,
        stream_id_hex: str,
        final_text: str,
        transcript_hash_hex: str,
        chunk_count: int,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_finalize",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "final_text": str(final_text or ""),
                "transcript_hash_hex": _normalize_hex(transcript_hash_hex, "transcript_hash_hex"),
                "chunk_count": int(chunk_count),
            }
        )

    async def stream_cancel(self, stream_id_hex: str, reason: Optional[str] = None) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_cancel",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "reason": reason,
            }
        )

    async def inbound_events(
        self,
        *,
        account_id_hex: Optional[str] = None,
        group_id_hex: Optional[str] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        request_id = uuid.uuid4().hex
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._write_envelope(
                writer,
                {
                    "type": "subscribe_inbound",
                    "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex") if account_id_hex else None,
                    "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex") if group_id_hex else None,
                },
                request_id=request_id,
            )
            ack = await self._read_envelope(reader)
            self._validate_response_id(ack, request_id)
            self._raise_if_error(ack)
            if ack.get("type") != "ack":
                raise AgentControlError(f"expected subscribe ack, got {ack.get('type')!r}")

            while True:
                envelope = await self._read_envelope(reader, allow_eof=True)
                if envelope is None:
                    return
                self._validate_response_id(envelope, request_id)
                self._raise_if_error(envelope)
                yield envelope
        except OSError as exc:
            raise AgentControlError(str(exc), code="socket_io", retryable=True) from exc
        finally:
            await _close_writer(writer)

    async def _write_envelope(self, writer: asyncio.StreamWriter, payload: Dict[str, Any], *, request_id: str) -> None:
        envelope = {
            "marmot_agent_control": PROTOCOL,
            "id": request_id,
            **payload,
        }
        frame = json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(frame) > MAX_FRAME_BYTES:
            raise AgentControlError("agent control frame is too large", code="frame_too_large")
        writer.write(frame)
        try:
            await asyncio.wait_for(writer.drain(), timeout=self.request_timeout)
        except asyncio.TimeoutError as exc:
            raise AgentControlError(
                "timed out while writing agent control request",
                code="timeout",
                retryable=True,
            ) from exc

    async def _read_envelope(
        self,
        reader: asyncio.StreamReader,
        *,
        allow_eof: bool = False,
    ) -> Optional[Dict[str, Any]]:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=self.request_timeout)
        except asyncio.TimeoutError as exc:
            raise AgentControlError(
                "timed out while reading agent control response",
                code="timeout",
                retryable=True,
            ) from exc
        if not raw:
            if allow_eof:
                return None
            raise AgentControlError("agent control socket closed", code="socket_closed", retryable=True)
        if len(raw) > MAX_FRAME_BYTES:
            raise AgentControlError("agent control frame is too large", code="frame_too_large")
        envelope = json.loads(raw.decode("utf-8"))
        if envelope.get("marmot_agent_control") != PROTOCOL:
            raise AgentControlError(
                f"wrong agent control protocol: {envelope.get('marmot_agent_control')!r}",
                code="wrong_protocol",
            )
        return envelope

    @staticmethod
    def _validate_response_id(envelope: Dict[str, Any], request_id: str) -> None:
        if envelope.get("id") != request_id:
            raise AgentControlError("agent control response id mismatch", code="id_mismatch")

    @staticmethod
    def _raise_if_error(envelope: Dict[str, Any]) -> None:
        if envelope.get("type") == "error":
            raise AgentControlError(
                str(envelope.get("message") or "agent control error"),
                code=str(envelope.get("code") or "agent_control_error"),
            )


class MarmotLiveStream:
    """Client-side state for one append-only Marmot live-preview stream."""

    def __init__(
        self,
        *,
        client: MarmotAgentControlClient,
        account_id_hex: str,
        group_id_hex: str,
        stream_id_hex: str,
        start_message_id_hex: str,
        chunk_bytes: int,
    ):
        self.client = client
        self.account_id_hex = account_id_hex
        self.group_id_hex = group_id_hex
        self.stream_id_hex = stream_id_hex
        self.start_message_id_hex = start_message_id_hex
        self.text = AppendOnlyTextState()
        self.transcript = AgentTextStreamTranscript(
            stream_id_hex,
            start_message_id_hex,
            chunk_bytes=chunk_bytes,
        )
        self.finalized = False

    @classmethod
    async def begin(
        cls,
        *,
        client: MarmotAgentControlClient,
        account_id_hex: str,
        group_id_hex: str,
        quic_candidates: Iterable[str],
        chunk_bytes: int,
        stream_id_hex: Optional[str] = None,
    ) -> "MarmotLiveStream":
        response = await client.stream_begin(
            account_id_hex,
            group_id_hex,
            stream_id_hex=stream_id_hex,
            quic_candidates=quic_candidates,
        )
        return cls(
            client=client,
            account_id_hex=account_id_hex,
            group_id_hex=group_id_hex,
            stream_id_hex=response["stream_id_hex"],
            start_message_id_hex=response["start_message_id_hex"],
            chunk_bytes=chunk_bytes,
        )

    async def append_replacement(self, next_text: str) -> None:
        suffix = self.text.suffix_for(next_text)
        if not suffix:
            return
        await self.client.stream_append(self.stream_id_hex, suffix)
        self.transcript.append_text(suffix)

    async def status(self, status: str) -> None:
        await self.client.stream_status(self.stream_id_hex, status)
        self.transcript.append_status(status)

    async def finalize(self, final_text: str) -> Dict[str, Any]:
        await self.append_replacement(final_text)
        response = await self.client.stream_finalize(
            self.stream_id_hex,
            final_text,
            self.transcript.hash_hex,
            self.transcript.chunk_count,
        )
        self.finalized = True
        return response

    async def cancel(self, reason: Optional[str] = None) -> None:
        if not self.finalized:
            await self.client.stream_cancel(self.stream_id_hex, reason)


class MarmotPlatformAdapter(BasePlatformAdapter):
    """Hermes adapter that exposes Marmot groups as a platform."""

    def __init__(self, config: PlatformConfig, client: Optional[MarmotAgentControlClient] = None):
        super().__init__(config, Platform("marmot"))
        extra = getattr(config, "extra", {}) or {}
        self.socket_path = resolve_socket_path(extra)
        self.client = client or MarmotAgentControlClient(self.socket_path)
        self.account_id_hex = _optional_hex(
            _first_config_value(extra, "account_id_hex", "account", env="MARMOT_ACCOUNT_ID_HEX"),
            "MARMOT_ACCOUNT_ID_HEX",
        )
        self.group_id_hex = _optional_hex(
            _first_config_value(extra, "group_id_hex", "group", env="MARMOT_GROUP_ID_HEX"),
            "MARMOT_GROUP_ID_HEX",
        )
        self.quic_candidates = resolve_quic_candidates(extra)
        self.stream_chunk_bytes = int(extra.get("stream_chunk_bytes") or DEFAULT_STREAM_CHUNK_BYTES)
        self.streaming_cursor = str(extra.get("streaming_cursor") or os.getenv("MARMOT_STREAMING_CURSOR") or DEFAULT_STREAMING_CURSOR)
        self._listener_task: Optional[asyncio.Task] = None
        self._active_streams: Dict[str, MarmotLiveStream] = {}
        self._draft_streams: Dict[tuple[str, int], MarmotLiveStream] = {}
        self._last_chat_stream: Dict[str, MarmotLiveStream] = {}

    @property
    def enforces_own_access_policy(self) -> bool:
        return True

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        chat_id = _normalize_hex(chat_id, "chat_id")
        return {
            "name": f"Marmot {chat_id[:12]}",
            "type": "group",
            "id": chat_id,
        }

    async def connect(self) -> bool:
        try:
            await self._ensure_account_id()
            self._listener_task = asyncio.create_task(self._consume_inbound_loop())
            self._mark_connected()
            return True
        except Exception as exc:
            logger.error("Failed to connect Marmot adapter: %s", exc)
            set_fatal = getattr(self, "_set_fatal_error", None)
            if callable(set_fatal):
                set_fatal("marmot_connect_failed", str(exc), retryable=True)
            return False

    async def disconnect(self) -> None:
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        await self._cancel_all_streams("adapter disconnect")
        self._mark_disconnected()

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        chat_id = _normalize_hex(chat_id, "chat_id")
        visible_content = self._strip_streaming_cursor(content)

        if self._looks_like_stream_preview(content):
            if not self.quic_candidates:
                return SendResult(success=False, error="Marmot live preview requires MARMOT_QUIC_CANDIDATES")
            try:
                stream = await self._begin_live_stream(chat_id)
                await stream.append_replacement(visible_content)
                message_id = _stream_message_id(stream.stream_id_hex)
                self._active_streams[message_id] = stream
                self._last_chat_stream[chat_id] = stream
                return SendResult(success=True, message_id=message_id)
            except Exception as exc:
                logger.debug("Marmot live-preview first send failed: %s", exc)
                return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

        await self._finalize_chat_streams(chat_id, visible_content)
        return await self._send_final_direct(
            chat_id,
            visible_content,
            reply_to_message_id_hex=_optional_hex(reply_to),
        )

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
    ) -> SendResult:
        stream = self._active_streams.get(message_id)
        if stream is None:
            return SendResult(success=False, error="Marmot cannot edit durable messages")

        chat_id = _normalize_hex(chat_id, "chat_id")
        visible_content = self._strip_streaming_cursor(content)
        try:
            await stream.append_replacement(visible_content)
            if not finalize:
                return SendResult(success=True, message_id=message_id)

            await stream.finalize(visible_content)
            self._active_streams.pop(message_id, None)
            self._forget_stream(chat_id, stream)
            return await self._send_final_direct(chat_id, visible_content)
        except NonAppendOnlyUpdate as exc:
            await self._cancel_stream(chat_id, message_id, stream, str(exc))
            if finalize:
                return await self._send_final_direct(chat_id, visible_content)
            return SendResult(success=False, error=str(exc), retryable=False)
        except Exception as exc:
            logger.debug("Marmot live-preview edit failed: %s", exc)
            return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

    def supports_draft_streaming(
        self,
        chat_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return bool(self.quic_candidates)

    async def send_draft(
        self,
        chat_id: str,
        draft_id: int,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if not self.quic_candidates:
            return SendResult(success=False, error="Marmot live preview requires MARMOT_QUIC_CANDIDATES")

        chat_id = _normalize_hex(chat_id, "chat_id")
        key = (chat_id, int(draft_id))
        visible_content = self._strip_streaming_cursor(content)
        try:
            stream = self._draft_streams.get(key)
            if stream is None:
                stream = await self._begin_live_stream(chat_id)
                self._draft_streams[key] = stream
                self._last_chat_stream[chat_id] = stream
            await stream.append_replacement(visible_content)
            return SendResult(success=True)
        except NonAppendOnlyUpdate as exc:
            stream = self._draft_streams.pop(key, None)
            if stream is not None:
                await self._cancel_stream(chat_id, None, stream, str(exc))
            return SendResult(success=False, error=str(exc), retryable=False)
        except Exception as exc:
            logger.debug("Marmot live-preview draft failed: %s", exc)
            return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

    async def _send_final_direct(
        self,
        chat_id: str,
        content: str,
        *,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> SendResult:
        try:
            account_id = await self._ensure_account_id()
            response = await self.client.send_final(
                account_id,
                chat_id,
                content,
                reply_to_message_id_hex=reply_to_message_id_hex,
            )
            message_ids = tuple(response.get("message_ids_hex") or ())
            message_id = message_ids[-1] if message_ids else None
            return SendResult(
                success=True,
                message_id=message_id,
                raw_response=response,
                continuation_message_ids=message_ids[:-1],
            )
        except Exception as exc:
            logger.debug("Marmot send_final failed: %s", exc)
            return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

    async def _begin_live_stream(self, chat_id: str) -> MarmotLiveStream:
        account_id = await self._ensure_account_id()
        return await MarmotLiveStream.begin(
            client=self.client,
            account_id_hex=account_id,
            group_id_hex=chat_id,
            quic_candidates=self.quic_candidates,
            chunk_bytes=self.stream_chunk_bytes,
        )

    async def _finalize_chat_streams(self, chat_id: str, final_text: str) -> None:
        stream = self._last_chat_stream.pop(chat_id, None)
        if stream is None or stream.finalized:
            return
        try:
            await stream.finalize(final_text)
        except NonAppendOnlyUpdate:
            await stream.cancel("final text was not append-only")
        except Exception as exc:
            logger.debug("Marmot live-preview finalize failed before final send: %s", exc)
        finally:
            self._remove_stream_refs(stream)

    async def _cancel_stream(
        self,
        chat_id: str,
        message_id: Optional[str],
        stream: MarmotLiveStream,
        reason: str,
    ) -> None:
        try:
            await stream.cancel(reason)
        except Exception:
            logger.debug("Marmot live-preview cancel failed", exc_info=True)
        if message_id:
            self._active_streams.pop(message_id, None)
        self._forget_stream(chat_id, stream)

    async def _cancel_all_streams(self, reason: str) -> None:
        streams = set(self._active_streams.values()) | set(self._draft_streams.values())
        for stream in streams:
            try:
                await stream.cancel(reason)
            except Exception:
                logger.debug("Marmot live-preview cancel failed", exc_info=True)
        self._active_streams.clear()
        self._draft_streams.clear()
        self._last_chat_stream.clear()

    def _forget_stream(self, chat_id: str, stream: MarmotLiveStream) -> None:
        if self._last_chat_stream.get(chat_id) is stream:
            self._last_chat_stream.pop(chat_id, None)
        self._remove_stream_refs(stream)

    def _remove_stream_refs(self, stream: MarmotLiveStream) -> None:
        for key, value in list(self._active_streams.items()):
            if value is stream:
                self._active_streams.pop(key, None)
        for key, value in list(self._draft_streams.items()):
            if value is stream:
                self._draft_streams.pop(key, None)

    async def _ensure_account_id(self) -> str:
        if self.account_id_hex:
            return self.account_id_hex
        response = await self.client.account_list()
        accounts = list(response.get("accounts") or [])
        if len(accounts) == 1:
            self.account_id_hex = _normalize_hex(accounts[0]["account_id_hex"], "account_id_hex")
            return self.account_id_hex
        if not accounts:
            raise AgentControlError("dm-agent has no local Marmot accounts; create one first", code="no_accounts")
        raise AgentControlError(
            "dm-agent has multiple accounts; set MARMOT_ACCOUNT_ID_HEX",
            code="ambiguous_account",
        )

    async def _consume_inbound_loop(self) -> None:
        while True:
            try:
                await self._consume_inbound_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Marmot inbound subscription failed, retrying: %s", exc)
                await asyncio.sleep(2.0)

    async def _consume_inbound_once(self) -> None:
        async for event in self.client.inbound_events(
            account_id_hex=self.account_id_hex,
            group_id_hex=self.group_id_hex,
        ):
            await self._handle_control_event(event)

    async def _handle_control_event(self, event: Dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type != "inbound_message":
            logger.debug("Ignoring Marmot control event type %s", event_type)
            return

        group_id_hex = event["group_id_hex"]
        sender_account_id_hex = event["sender_account_id_hex"]
        message_id_hex = event["message_id_hex"]
        source = self.build_source(
            chat_id=group_id_hex,
            chat_name=f"Marmot {group_id_hex[:12]}",
            chat_type="group",
            user_id=sender_account_id_hex,
            user_name=f"Marmot {sender_account_id_hex[:12]}",
            message_id=message_id_hex,
        )
        hermes_event = MessageEvent(
            text=str(event.get("text") or ""),
            message_type=MessageType.TEXT,
            source=source,
            raw_message=event,
            message_id=message_id_hex,
        )
        await self.handle_message(hermes_event)

    def _looks_like_stream_preview(self, content: str) -> bool:
        return bool(self.streaming_cursor and str(content or "").rstrip().endswith(self.streaming_cursor))

    def _strip_streaming_cursor(self, content: str) -> str:
        text = str(content or "")
        cursor = self.streaming_cursor
        if cursor and text.rstrip().endswith(cursor):
            trailing_len = len(text) - len(text.rstrip())
            stripped = text.rstrip()
            text = stripped[: -len(cursor)]
            if trailing_len:
                text += " " * trailing_len
        return text


def check_requirements() -> bool:
    return validate_config(_MinimalConfig(extra={}))


def validate_config(config) -> bool:
    extra = getattr(config, "extra", {}) or {}
    return bool(
        os.getenv("MARMOT_AGENT_SOCKET")
        or os.getenv("MARMOT_HOME")
        or _first_config_value(extra, "socket_path", "agent_socket", "socket")
        or _first_config_value(extra, "home", "marmot_home")
        or Path(resolve_socket_path(extra)).exists()
    )


def _env_enablement() -> Optional[Dict[str, Any]]:
    socket = os.getenv("MARMOT_AGENT_SOCKET", "").strip()
    home = os.getenv("MARMOT_HOME", "").strip()
    account = os.getenv("MARMOT_ACCOUNT_ID_HEX", "").strip()
    group = os.getenv("MARMOT_GROUP_ID_HEX", "").strip()
    candidates = os.getenv("MARMOT_QUIC_CANDIDATES", "").strip() or os.getenv("MARMOT_QUIC_CANDIDATE", "").strip()
    if not (socket or home):
        return None

    seed: Dict[str, Any] = {}
    if socket:
        seed["socket_path"] = socket
    if home:
        seed["home"] = home
    if account:
        seed["account_id_hex"] = account
    if group:
        seed["group_id_hex"] = group
    if candidates:
        seed["quic_candidates"] = _split_config_list(candidates)

    home_channel = os.getenv("MARMOT_HOME_CHANNEL", "").strip()
    if home_channel:
        seed["home_channel"] = {
            "chat_id": home_channel,
            "name": os.getenv("MARMOT_HOME_CHANNEL_NAME", "Marmot"),
        }
    return seed


async def _standalone_send(
    pconfig,
    chat_id,
    message,
    *,
    thread_id=None,
    media_files=None,
    force_document=False,
):
    adapter = MarmotPlatformAdapter(pconfig)
    result = await adapter.send(str(chat_id), str(message or ""))
    if result.success:
        return {"success": True, "message_id": result.message_id}
    return {"error": result.error or "Marmot send failed"}


def register(ctx):
    """Hermes plugin entry point."""
    ctx.register_platform(
        name="marmot",
        label="Marmot",
        adapter_factory=lambda cfg: MarmotPlatformAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="MARMOT_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="MARMOT_ALLOWED_USERS",
        allow_all_env="MARMOT_ALLOW_ALL_USERS",
        max_message_length=0,
        platform_hint=(
            "You are chatting through Marmot, an end-to-end encrypted group "
            "messaging protocol. Chat ids are Marmot group ids and user ids "
            "are Marmot account pubkeys."
        ),
        emoji="",
    )


def resolve_socket_path(extra: Dict[str, Any]) -> str:
    configured = _first_config_value(extra, "socket_path", "agent_socket", "socket", env="MARMOT_AGENT_SOCKET")
    if configured:
        return str(Path(str(configured)).expanduser())

    home = _first_config_value(extra, "home", "marmot_home", env="MARMOT_HOME") or DEFAULT_SOCKET_HOME
    return str(Path(str(home)).expanduser() / "dev" / "dm-agent.sock")


def resolve_quic_candidates(extra: Dict[str, Any]) -> list[str]:
    configured = extra.get("quic_candidates")
    if configured is None:
        configured = os.getenv("MARMOT_QUIC_CANDIDATES") or os.getenv("MARMOT_QUIC_CANDIDATE")
    return [candidate for candidate in _split_config_list(configured) if candidate.startswith("quic://")]


def split_text_deltas(text: str, max_chunk_bytes: int) -> list[bytes]:
    if max_chunk_bytes <= 0:
        raise ValueError("max_chunk_bytes must be positive")
    text = str(text or "")
    if not text:
        return []

    chunks: list[bytes] = []
    current: list[str] = []
    current_len = 0
    for ch in text:
        encoded = ch.encode("utf-8")
        if current and current_len + len(encoded) > max_chunk_bytes:
            chunks.append("".join(current).encode("utf-8"))
            current = []
            current_len = 0
        if not current and len(encoded) > max_chunk_bytes:
            chunks.append(encoded)
            continue
        current.append(ch)
        current_len += len(encoded)
    if current:
        chunks.append("".join(current).encode("utf-8"))
    return chunks


def is_retryable(exc: BaseException) -> bool:
    return bool(getattr(exc, "retryable", False) or isinstance(exc, OSError))


def _normalize_hex(value: Any, field: str = "hex") -> str:
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        raise AgentControlError(f"{field} must not be empty", code="invalid_hex")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise AgentControlError(f"{field} must be hexadecimal", code="invalid_hex") from exc
    return text


def _optional_hex(value: Any, field: str = "hex") -> Optional[str]:
    if value is None or str(value).strip() == "":
        return None
    return _normalize_hex(value, field)


def _hash_len_prefixed(hasher: Any, data: bytes) -> None:
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def _split_config_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _first_config_value(extra: Dict[str, Any], *keys: str, env: Optional[str] = None) -> Any:
    if env:
        value = os.getenv(env)
        if value:
            return value
    for key in keys:
        value = extra.get(key)
        if value:
            return value
    return None


def _stream_message_id(stream_id_hex: str) -> str:
    return f"{STREAM_MESSAGE_PREFIX}{stream_id_hex}"


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception as exc:
        logger.debug("error while closing Marmot socket writer: %s", exc)


class _MinimalConfig:
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        self.extra = extra or {}
