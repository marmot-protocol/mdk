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
import re
import uuid
from collections import OrderedDict
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
TOOL_PROGRESS_MESSAGE_PREFIX = "marmot-tool-progress:"
TOOL_EVENT_PREFIX = "\x1fMARMOT_TOOL_EVENT:"
DEFAULT_STREAMING_CURSOR = "\u2589"
_DEFAULT_READ_TIMEOUT = object()
MAX_TOOL_PROGRESS_MESSAGES = 512
MAX_PROFILE_NAME_CHARS = 80
PROFILE_NAME_PROMPT = (
    "I do not have a public Nostr profile name yet. What should I publish as "
    'this agent\'s display name? Reply with a name, or reply "skip" to stay unnamed.'
)
PROFILE_NAME_PUBLISHED = "Done. I published this agent's public Nostr profile name as \"{name}\"."
PROFILE_NAME_SKIPPED = "Okay, I will stay unnamed for now."
PROFILE_NAME_EMPTY = 'Please reply with a name, or reply "skip" to stay unnamed.'
PROFILE_NAME_TOO_LONG = 'That name is too long. Please reply with a shorter name, or reply "skip" to stay unnamed.'
PROFILE_NAME_PUBLISH_FAILED = "I could not publish that profile name yet. Please try again later."
PROFILE_NAME_SKIP_REPLIES = {
    "/skip",
    "cancel",
    "no",
    "no thanks",
    "not now",
    "skip",
}
LEGACY_TOOL_PROGRESS_RE = re.compile(
    r'^\S+\s+(?P<tool>[A-Za-z0-9_.-]+)(?:\([^)]*\))?(?:(?::\s+"(?P<preview>.*)")|(?:\.\.\.))$',
    re.DOTALL,
)


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


class ProfileNameOnboardingStore:
    """Tiny local state file for the one-time public profile-name consent flow."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._lock = asyncio.Lock()

    async def get(self, account_id_hex: str) -> Dict[str, Any]:
        async with self._lock:
            data = self._read()
            return dict((data.get("accounts") or {}).get(account_id_hex) or {})

    async def mark_prompted(self, account_id_hex: str, group_id_hex: str) -> None:
        await self._set(
            account_id_hex,
            {
                "status": "prompted",
                "group_id_hex": group_id_hex,
            },
        )

    async def mark_published(self, account_id_hex: str, name: str) -> None:
        await self._set(
            account_id_hex,
            {
                "status": "published",
                "name": name,
            },
        )

    async def mark_skipped(self, account_id_hex: str) -> None:
        await self._set(account_id_hex, {"status": "skipped"})

    async def _set(self, account_id_hex: str, record: Dict[str, Any]) -> None:
        async with self._lock:
            data = self._read()
            accounts = data.setdefault("accounts", {})
            accounts[account_id_hex] = record
            self._write(data)

    def _read(self) -> Dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"marmot_profile_onboarding": "v1", "accounts": {}}
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {"marmot_profile_onboarding": "v1", "accounts": {}}
        data.setdefault("marmot_profile_onboarding", "v1")
        accounts = data.get("accounts")
        if not isinstance(accounts, dict):
            data["accounts"] = {}
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_name(f"{self.path.name}.tmp")
        tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, self.path)


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

    def __init__(self, socket_path: str | Path, *, request_timeout: float = 30.0, auth_token: Optional[str] = None):
        self.socket_path = str(Path(socket_path).expanduser())
        self.request_timeout = float(request_timeout)
        self.auth_token = str(auth_token).strip() if auth_token else None

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

    async def account_publish_profile(
        self,
        account_id_hex: str,
        name: str,
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "account_publish_profile",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "name": str(name or ""),
                "display_name": str(display_name) if display_name is not None else None,
            }
        )

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

    async def stream_tool(self, stream_id_hex: str, text: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_tool",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "text": str(text or ""),
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

    async def send_agent_activity(
        self,
        account_id_hex: str,
        group_id_hex: str,
        *,
        status: str,
        text: str,
        reply_to_message_id_hex: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "send_agent_activity",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "status": str(status or ""),
                "text": str(text or ""),
                "reply_to_message_id_hex": _normalize_hex(reply_to_message_id_hex, "reply_to_message_id_hex")
                if reply_to_message_id_hex
                else None,
                "extra": extra,
            }
        )

    async def send_agent_operation_event(
        self,
        account_id_hex: str,
        group_id_hex: str,
        *,
        event_type: str,
        status: str,
        operation_id: Optional[str] = None,
        run_id: Optional[str] = None,
        turn_id: Optional[str] = None,
        name: Optional[str] = None,
        text: str = "",
        preview: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        sequence: Optional[int] = None,
        ok: Optional[bool] = None,
        duration_ms: Optional[int] = None,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "send_agent_operation_event",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "event_type": str(event_type or ""),
                "status": str(status or ""),
                "operation_id": str(operation_id).strip() if operation_id else None,
                "run_id": str(run_id).strip() if run_id else None,
                "turn_id": str(turn_id).strip() if turn_id else None,
                "name": str(name).strip() if name else None,
                "text": str(text or ""),
                "preview": str(preview) if preview is not None else None,
                "details": details,
                "sequence": int(sequence) if sequence is not None else None,
                "ok": bool(ok) if ok is not None else None,
                "duration_ms": int(duration_ms) if duration_ms is not None else None,
                "reply_to_message_id_hex": _normalize_hex(reply_to_message_id_hex, "reply_to_message_id_hex")
                if reply_to_message_id_hex
                else None,
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
                envelope = await self._read_envelope(reader, allow_eof=True, timeout=None)
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
        if self.auth_token:
            envelope["auth_token"] = self.auth_token
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
        timeout: Any = _DEFAULT_READ_TIMEOUT,
    ) -> Optional[Dict[str, Any]]:
        read_timeout = self.request_timeout if timeout is _DEFAULT_READ_TIMEOUT else timeout
        try:
            if read_timeout is None:
                raw = await reader.readline()
            else:
                raw = await asyncio.wait_for(reader.readline(), timeout=float(read_timeout))
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
        self.client = client or MarmotAgentControlClient(self.socket_path, auth_token=resolve_auth_token(extra))
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
        self.profile_name_onboarding_enabled = resolve_profile_name_onboarding_enabled(extra)
        self.profile_name_onboarding = (
            ProfileNameOnboardingStore(resolve_profile_onboarding_state_path(extra, self.socket_path))
            if self.profile_name_onboarding_enabled
            else None
        )
        self._listener_task: Optional[asyncio.Task] = None
        self._active_streams: Dict[str, MarmotLiveStream] = {}
        self._draft_streams: Dict[tuple[str, int], MarmotLiveStream] = {}
        self._last_chat_stream: Dict[str, MarmotLiveStream] = {}
        self._tool_progress_events: OrderedDict[str, set[str]] = OrderedDict()
        self._tool_progress_replies: Dict[str, Optional[str]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

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
        self._tool_progress_events.clear()
        self._tool_progress_replies.clear()
        self._mark_disconnected()

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        self._capture_loop()
        chat_id = _normalize_hex(chat_id, "chat_id")
        visible_content = self._strip_streaming_cursor(content)

        tool_events = _tool_events_from_progress_text(visible_content)
        if tool_events:
            return await self._send_tool_progress_events(
                chat_id,
                tool_events,
                reply_to_message_id_hex=_optional_hex(reply_to),
            )

        if self._looks_like_stream_preview(content):
            if not self.quic_candidates:
                return SendResult(success=False, error="Marmot live preview requires MARMOT_QUIC_CANDIDATES")
            try:
                await self._cancel_other_chat_streams(chat_id, reason="superseded by newer preview")
                stream = await self._begin_live_stream(chat_id)
                await stream.append_replacement(visible_content)
                message_id = _stream_message_id(stream.stream_id_hex)
                self._active_streams[message_id] = stream
                self._last_chat_stream[chat_id] = stream
                return SendResult(success=True, message_id=message_id)
            except Exception as exc:
                logger.debug("Marmot live-preview first send failed: %s", exc)
                return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

        stream = self._last_chat_stream.get(chat_id)
        if stream is not None and not stream.finalized:
            message_id = _stream_message_id(stream.stream_id_hex)
            try:
                # The final text is authoritative. Finalize the live preview only
                # when the final is an exact append-only extension of the streamed
                # text; otherwise drop the preview and send the final verbatim.
                return await self._finalize_active_stream(
                    chat_id,
                    stream,
                    visible_content,
                    message_id=message_id,
                )
            except NonAppendOnlyUpdate:
                await self._cancel_stream(
                    chat_id,
                    message_id,
                    stream,
                    "final text was not append-only",
                )
                return await self._send_final_direct(
                    chat_id,
                    visible_content,
                    reply_to_message_id_hex=_optional_hex(reply_to),
                )
            except Exception as exc:
                logger.debug("Marmot live-preview finalize failed: %s", exc)
                return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

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
        self._capture_loop()
        if message_id.startswith(TOOL_PROGRESS_MESSAGE_PREFIX):
            chat_id = _normalize_hex(chat_id, "chat_id")
            visible_content = self._strip_streaming_cursor(content)
            tool_events = _tool_events_from_progress_text(visible_content)
            if not tool_events:
                return SendResult(success=True, message_id=message_id)
            return await self._send_tool_progress_events(
                chat_id,
                tool_events,
                message_id=message_id,
            )

        stream = self._active_streams.get(message_id)
        if stream is None:
            return SendResult(success=False, error="Marmot cannot edit durable messages")

        chat_id = _normalize_hex(chat_id, "chat_id")
        visible_content = self._strip_streaming_cursor(content)
        try:
            await stream.append_replacement(visible_content)
            if not finalize:
                return SendResult(success=True, message_id=message_id)

            return await self._finalize_active_stream(
                chat_id,
                stream,
                visible_content,
                message_id=message_id,
            )
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

    def render_message_event(self, event: Any, sink: Any) -> None:
        try:
            from gateway.stream_events import Commentary, MessageChunk, MessageStop
        except Exception:
            return super().render_message_event(event, sink)

        if isinstance(event, MessageChunk):
            if event.text:
                sink.on_delta(event.text)
            return
        if isinstance(event, MessageStop):
            if not event.final:
                sink.on_segment_break()
            return
        if isinstance(event, Commentary):
            text = str(getattr(event, "text", "") or "")
            if text.strip():
                self._schedule_agent_activity(
                    getattr(sink, "chat_id", ""),
                    status="commentary",
                    text=text,
                    reply_to_message_id_hex=getattr(sink, "_initial_reply_to_id", None),
                )
            return

        return super().render_message_event(event, sink)

    def format_tool_event(self, event: Any, *, mode: str = "all", preview_max_len: int = 40) -> Optional[str]:
        tool_name = str(getattr(event, "tool_name", "") or "").strip()
        if not tool_name:
            return None
        preview = getattr(event, "preview", None)
        args = getattr(event, "args", None)
        payload: Dict[str, Any] = {
            "event_type": "tool_call",
            "status": "started",
            "name": tool_name,
            "text": _tool_event_text(tool_name, preview),
            "preview": str(preview) if preview is not None else None,
            "details": {"args": args} if isinstance(args, dict) else None,
            "sequence": getattr(event, "index", None),
        }
        return _encoded_tool_event({key: value for key, value in payload.items() if value is not None})

    async def send_draft(
        self,
        chat_id: str,
        draft_id: int,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        self._capture_loop()
        if not self.quic_candidates:
            return SendResult(success=False, error="Marmot live preview requires MARMOT_QUIC_CANDIDATES")

        chat_id = _normalize_hex(chat_id, "chat_id")
        key = (chat_id, int(draft_id))
        visible_content = self._strip_streaming_cursor(content)
        if not visible_content.strip():
            stream = self._draft_streams.pop(key, None)
            if stream is not None:
                await self._cancel_stream(chat_id, None, stream, "draft cleared")
            return SendResult(success=True)

        try:
            stream = self._draft_streams.get(key)
            if stream is None:
                await self._cancel_other_draft_streams(
                    chat_id,
                    keep_key=key,
                    reason="superseded by newer draft",
                )
                await self._cancel_other_chat_streams(chat_id, reason="superseded by newer draft")
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

    async def _finalize_active_stream(
        self,
        chat_id: str,
        stream: MarmotLiveStream,
        final_text: str,
        *,
        message_id: Optional[str] = None,
    ) -> SendResult:
        response = await stream.finalize(final_text)
        if message_id:
            self._active_streams.pop(message_id, None)
        self._forget_stream(chat_id, stream)
        return self._result_from_stream_finalize(response)

    @staticmethod
    def _result_from_stream_finalize(response: Dict[str, Any]) -> SendResult:
        message_ids = tuple(response.get("message_ids_hex") or ())
        message_id = message_ids[-1] if message_ids else None
        if response.get("type") != "stream_finalized" or not message_ids:
            raise AgentControlError(
                "Marmot stream finalize returned no message ids",
                code="unexpected_stream_finalize_response",
                retryable=True,
            )
        return SendResult(
            success=True,
            message_id=message_id,
            raw_response=response,
            continuation_message_ids=message_ids[:-1],
        )

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

    async def _send_tool_progress_events(
        self,
        chat_id: str,
        events: Iterable[Dict[str, Any]],
        *,
        reply_to_message_id_hex: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> SendResult:
        message_id = message_id or _tool_progress_message_id()
        seen = self._tool_progress_seen(message_id)
        if reply_to_message_id_hex is not None or message_id not in self._tool_progress_replies:
            self._tool_progress_replies[message_id] = reply_to_message_id_hex
        else:
            reply_to_message_id_hex = self._tool_progress_replies[message_id]
        sent_message_ids = []
        try:
            account_id = await self._ensure_account_id()
            for event in events:
                key = json.dumps(event, sort_keys=True, separators=(",", ":"))
                if key in seen:
                    continue
                response = await self.client.send_agent_operation_event(
                    account_id,
                    chat_id,
                    event_type=str(event.get("event_type") or "tool_call"),
                    status=str(event.get("status") or "started"),
                    operation_id=event.get("operation_id"),
                    run_id=event.get("run_id"),
                    turn_id=event.get("turn_id"),
                    name=event.get("name"),
                    text=str(event.get("text") or ""),
                    preview=event.get("preview"),
                    details=event.get("details") if isinstance(event.get("details"), dict) else None,
                    sequence=event.get("sequence"),
                    ok=event.get("ok"),
                    duration_ms=event.get("duration_ms"),
                    reply_to_message_id_hex=reply_to_message_id_hex,
                )
                message_ids = tuple(response.get("message_ids_hex") or ())
                if response.get("type") != "app_event_sent" or not message_ids:
                    raise AgentControlError(
                        "Marmot agent operation event send returned no message ids",
                        code="unexpected_operation_event_response",
                        retryable=True,
                    )
                seen.add(key)
                sent_message_ids.extend(message_ids)
            return SendResult(
                success=True,
                message_id=message_id,
                raw_response={"type": "tool_progress_sent", "message_ids_hex": sent_message_ids},
            )
        except Exception as exc:
            logger.debug("Marmot send_agent_operation_event failed: %s", exc)
            return SendResult(success=False, message_id=message_id, error=str(exc), retryable=is_retryable(exc))

    def _tool_progress_seen(self, message_id: str) -> set[str]:
        seen = self._tool_progress_events.get(message_id)
        if seen is None:
            seen = set()
            self._tool_progress_events[message_id] = seen
        else:
            self._tool_progress_events.move_to_end(message_id)
        while len(self._tool_progress_events) > MAX_TOOL_PROGRESS_MESSAGES:
            dropped_message_id, _ = self._tool_progress_events.popitem(last=False)
            self._tool_progress_replies.pop(dropped_message_id, None)
        return seen

    async def _begin_live_stream(self, chat_id: str) -> MarmotLiveStream:
        account_id = await self._ensure_account_id()
        return await MarmotLiveStream.begin(
            client=self.client,
            account_id_hex=account_id,
            group_id_hex=chat_id,
            quic_candidates=self.quic_candidates,
            chunk_bytes=self.stream_chunk_bytes,
        )

    async def _cancel_other_chat_streams(
        self,
        chat_id: str,
        *,
        keep: Optional[MarmotLiveStream] = None,
        reason: str = "superseded by newer stream",
    ) -> None:
        chat_id = _normalize_hex(chat_id, "chat_id")
        pending: list[tuple[Optional[str], MarmotLiveStream]] = []

        last = self._last_chat_stream.get(chat_id)
        if last is not None and last is not keep:
            pending.append((None, last))

        for message_id, stream in list(self._active_streams.items()):
            if stream is keep or stream.group_id_hex != chat_id:
                continue
            pending.append((message_id, stream))

        for (draft_chat_id, _draft_id), stream in list(self._draft_streams.items()):
            if stream is keep or draft_chat_id != chat_id:
                continue
            pending.append((None, stream))

        seen: set[int] = set()
        for message_id, stream in pending:
            token = id(stream)
            if token in seen:
                continue
            seen.add(token)
            await self._cancel_stream(chat_id, message_id, stream, reason)

    def _capture_loop(self) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

    def _schedule_agent_activity(
        self,
        chat_id: str,
        *,
        status: str,
        text: str,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> None:
        loop = self._loop
        if loop is None or not loop.is_running():
            try:
                loop = asyncio.get_running_loop()
                self._loop = loop
            except RuntimeError:
                return
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._send_agent_activity_event(
                    chat_id,
                    status=status,
                    text=text,
                    reply_to_message_id_hex=reply_to_message_id_hex,
                ),
                loop,
            )
            future.add_done_callback(_log_scheduled_activity_error)
        except Exception:
            logger.debug("Marmot agent activity scheduling failed", exc_info=True)

    async def _send_agent_activity_event(
        self,
        chat_id: str,
        *,
        status: str,
        text: str,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> None:
        account_id = await self._ensure_account_id()
        await self.client.send_agent_activity(
            account_id,
            _normalize_hex(chat_id, "chat_id"),
            status=status,
            text=text,
            reply_to_message_id_hex=_optional_hex(reply_to_message_id_hex, "reply_to_message_id_hex"),
        )

    async def _cancel_other_draft_streams(
        self,
        chat_id: str,
        *,
        keep_key: tuple[str, int],
        reason: str,
    ) -> None:
        stale_keys = [
            key
            for key in self._draft_streams
            if key[0] == chat_id and key != keep_key
        ]
        for key in stale_keys:
            stream = self._draft_streams.get(key)
            if stream is not None:
                await self._cancel_stream(chat_id, None, stream, reason)

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
        if await self._maybe_handle_profile_name_onboarding(event):
            return

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

    async def _maybe_handle_profile_name_onboarding(self, event: Dict[str, Any]) -> bool:
        store = self.profile_name_onboarding
        if store is None:
            return False

        try:
            account_id_hex = _normalize_hex(event["account_id_hex"], "account_id_hex")
            group_id_hex = _normalize_hex(event["group_id_hex"], "group_id_hex")
            message_id_hex = _normalize_hex(event["message_id_hex"], "message_id_hex")
            state = await store.get(account_id_hex)
            status = state.get("status")
            if status in {"published", "skipped"}:
                return False
            if status == "prompted":
                if state.get("group_id_hex") != group_id_hex:
                    return False
                return await self._handle_profile_name_reply(
                    account_id_hex,
                    group_id_hex,
                    message_id_hex,
                    str(event.get("text") or ""),
                )

            result = await self._send_final_direct(
                group_id_hex,
                PROFILE_NAME_PROMPT,
                reply_to_message_id_hex=message_id_hex,
            )
            if not result.success:
                logger.debug("Marmot profile-name prompt send failed: %s", result.error)
                return False
            await store.mark_prompted(account_id_hex, group_id_hex)
            return True
        except Exception as exc:
            logger.debug("Marmot profile-name onboarding failed: %s", exc)
            return False

    async def _handle_profile_name_reply(
        self,
        account_id_hex: str,
        group_id_hex: str,
        message_id_hex: str,
        text: str,
    ) -> bool:
        store = self.profile_name_onboarding
        if store is None:
            return False

        action, name, response = parse_profile_name_reply(text)
        if action == "skip":
            await store.mark_skipped(account_id_hex)
            await self._send_final_direct(
                group_id_hex,
                PROFILE_NAME_SKIPPED,
                reply_to_message_id_hex=message_id_hex,
            )
            return True
        if action == "invalid":
            await self._send_final_direct(
                group_id_hex,
                response,
                reply_to_message_id_hex=message_id_hex,
            )
            return True

        try:
            await self.client.account_publish_profile(account_id_hex, name, name)
            await store.mark_published(account_id_hex, name)
            await self._send_final_direct(
                group_id_hex,
                PROFILE_NAME_PUBLISHED.format(name=name),
                reply_to_message_id_hex=message_id_hex,
            )
        except Exception as exc:
            logger.debug("Marmot profile-name publish failed: %s", exc)
            await self._send_final_direct(
                group_id_hex,
                PROFILE_NAME_PUBLISH_FAILED,
                reply_to_message_id_hex=message_id_hex,
            )
        return True

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
    auth_token_file = os.getenv("MARMOT_AGENT_AUTH_TOKEN_FILE", "").strip()
    if auth_token_file:
        seed["auth_token_file"] = auth_token_file

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


def resolve_auth_token(extra: Dict[str, Any]) -> Optional[str]:
    configured = _first_config_value(extra, "auth_token", "agent_auth_token", env="MARMOT_AGENT_AUTH_TOKEN")
    if configured:
        token = str(configured).strip()
        if token:
            return token

    configured_path = _first_config_value(
        extra,
        "auth_token_file",
        "agent_auth_token_file",
        env="MARMOT_AGENT_AUTH_TOKEN_FILE",
    )
    if not configured_path:
        return None

    path = Path(str(configured_path)).expanduser()
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AgentControlError(
            f"failed to read Marmot agent auth token file: {path}",
            code="auth_token_file",
            retryable=True,
        ) from exc
    if not token:
        raise AgentControlError("Marmot agent auth token file is empty", code="auth_token_file")
    return token


def resolve_quic_candidates(extra: Dict[str, Any]) -> list[str]:
    configured = extra.get("quic_candidates")
    if configured is None:
        configured = os.getenv("MARMOT_QUIC_CANDIDATES") or os.getenv("MARMOT_QUIC_CANDIDATE")
    return [candidate for candidate in _split_config_list(configured) if candidate.startswith("quic://")]


def resolve_profile_name_onboarding_enabled(extra: Dict[str, Any]) -> bool:
    configured = os.getenv("MARMOT_PROFILE_NAME_ONBOARDING")
    if configured is None:
        for key in ("profile_name_onboarding", "profile_onboarding"):
            if key in extra:
                configured = extra[key]
                break
    return _config_bool(configured, default=False)


def resolve_profile_onboarding_state_path(extra: Dict[str, Any], socket_path: str | Path) -> Path:
    configured = _first_config_value(
        extra,
        "profile_onboarding_state_path",
        "profile_name_state_path",
        env="MARMOT_PROFILE_ONBOARDING_STATE",
    )
    if configured:
        return Path(str(configured)).expanduser()

    home = _first_config_value(extra, "home", "marmot_home", env="MARMOT_HOME")
    if home:
        return Path(str(home)).expanduser() / "dev" / "profile-onboarding.json"
    return Path(socket_path).expanduser().parent / "profile-onboarding.json"


def parse_profile_name_reply(text: str) -> tuple[str, Optional[str], str]:
    value = " ".join(str(text or "").split())
    if not value:
        return ("invalid", None, PROFILE_NAME_EMPTY)
    if value.casefold() in PROFILE_NAME_SKIP_REPLIES:
        return ("skip", None, PROFILE_NAME_SKIPPED)
    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        value = " ".join(value[1:-1].split())
    if not value:
        return ("invalid", None, PROFILE_NAME_EMPTY)
    if len(value) > MAX_PROFILE_NAME_CHARS:
        return ("invalid", None, PROFILE_NAME_TOO_LONG)
    return ("name", value, "")


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


def _config_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().casefold()
    if not text:
        return default
    return text not in {"0", "false", "no", "off", "disabled"}


def _stream_message_id(stream_id_hex: str) -> str:
    return f"{STREAM_MESSAGE_PREFIX}{stream_id_hex}"


def _tool_progress_message_id() -> str:
    return f"{TOOL_PROGRESS_MESSAGE_PREFIX}{uuid.uuid4().hex}"


def _tool_event_text(tool_name: str, preview: Any = None) -> str:
    if preview is None or str(preview).strip() == "":
        return f"{tool_name} started"
    return f"{tool_name}: {preview}"


def _encoded_tool_event(event: Dict[str, Any]) -> str:
    return TOOL_EVENT_PREFIX + json.dumps(event, sort_keys=True, separators=(",", ":"))


def _tool_events_from_progress_text(content: str) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    for block in _progress_blocks(content):
        if block.startswith(TOOL_EVENT_PREFIX):
            try:
                event = json.loads(block[len(TOOL_EVENT_PREFIX):])
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(_normalize_tool_event(event, fallback_text=block))
            continue

        event = _legacy_tool_event_from_progress_block(block)
        if event is not None:
            events.append(event)
    return events


def _progress_blocks(content: str) -> list[str]:
    text = str(content or "").strip()
    if not text:
        return []
    if TOOL_EVENT_PREFIX in text:
        return [line.strip() for line in text.splitlines() if line.strip()]
    return [block.strip() for block in text.split("\n") if block.strip()]


def _legacy_tool_event_from_progress_block(block: str) -> Optional[Dict[str, Any]]:
    match = LEGACY_TOOL_PROGRESS_RE.match(block)
    if not match:
        return None
    tool_name = (match.group("tool") or "").strip()
    if not tool_name:
        return None
    preview = match.group("preview")
    return _normalize_tool_event(
        {
            "event_type": "tool_call",
            "status": "started",
            "name": tool_name,
            "text": block,
            "preview": preview,
        },
        fallback_text=block,
    )


def _normalize_tool_event(event: Dict[str, Any], *, fallback_text: str) -> Dict[str, Any]:
    normalized = {
        "event_type": str(event.get("event_type") or "tool_call"),
        "status": str(event.get("status") or "started"),
        "text": str(event.get("text") or fallback_text or ""),
    }
    name = str(event.get("name") or event.get("tool_name") or "").strip()
    if name:
        normalized["name"] = name
    for field in ("operation_id", "run_id", "turn_id"):
        value = str(event.get(field) or "").strip()
        if value:
            normalized[field] = value
    preview = event.get("preview")
    if preview is not None:
        normalized["preview"] = str(preview)
    details = event.get("details")
    if isinstance(details, dict):
        normalized["details"] = details
    else:
        args = event.get("args")
        if isinstance(args, dict):
            normalized["details"] = {"args": args}
    for field in ("sequence", "duration_ms"):
        if event.get(field) is not None:
            try:
                normalized[field] = int(event[field])
            except (TypeError, ValueError):
                pass
    if "sequence" not in normalized and event.get("call_index") is not None:
        try:
            normalized["sequence"] = int(event["call_index"])
        except (TypeError, ValueError):
            pass
    if event.get("ok") is not None:
        normalized["ok"] = bool(event["ok"])
    return normalized


def _log_scheduled_activity_error(future) -> None:
    try:
        future.result()
    except Exception:
        logger.debug("Marmot scheduled agent activity failed", exc_info=True)


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception as exc:
        logger.debug("error while closing Marmot socket writer: %s", exc)


class _MinimalConfig:
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        self.extra = extra or {}
