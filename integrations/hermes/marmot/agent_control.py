"""Hardened NDJSON client for the local ``wn-agent`` control socket.

This module owns only v2 framing, request/response correlation, and typed
control requests. The Hermes platform behavior remains in :mod:`adapter`.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Optional

PROTOCOL = "marmot.agent-control.v2"
MAX_FRAME_BYTES = 1024 * 1024
SEND_MEDIA_COMPLETION_TIMEOUT_S = 15 * 60.0
_DEFAULT_READ_TIMEOUT = object()

class AgentControlError(RuntimeError):
    """Raised when the local ``wn-agent`` control socket rejects a request."""

    def __init__(self, message: str, *, code: str = "agent_control_error", retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable



class MarmotAgentControlClient:
    """Small NDJSON client for ``crates/agent-control``."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        request_timeout: float = 30.0,
        preview_request_timeout: float = 8.0,
        auth_token: Optional[str] = None,
    ):
        self.socket_path = str(Path(socket_path).expanduser())
        self.request_timeout = float(request_timeout)
        # Best-effort live-preview ops use a short timeout so a wedged preview
        # broker abandons the preview in a few seconds instead of pinning the
        # agent turn for the full request_timeout per op (mirrors client.ts
        # DEFAULT_PREVIEW_REQUEST_TIMEOUT_MS).
        self.preview_request_timeout = float(preview_request_timeout)
        self.auth_token = str(auth_token).strip() if auth_token else None

    async def request(
        self,
        payload: Dict[str, Any],
        *,
        request_id: Optional[str] = None,
        timeout: Optional[float] = None,
        response_timeout: Any = _DEFAULT_READ_TIMEOUT,
    ) -> Dict[str, Any]:
        request_id = request_id or uuid.uuid4().hex
        effective_timeout = self.request_timeout if timeout is None else float(timeout)
        effective_response_timeout = (
            effective_timeout if response_timeout is _DEFAULT_READ_TIMEOUT else response_timeout
        )
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._write_envelope(writer, payload, request_id=request_id, timeout=effective_timeout)
            response = await self._read_envelope(reader, timeout=effective_response_timeout)
            self._validate_response_id(response, request_id)
            self._raise_if_error(response)
            return response
        except OSError as exc:
            raise AgentControlError(str(exc), code="socket_io", retryable=True) from exc
        finally:
            await _close_writer(writer)

    async def account_list(self) -> Dict[str, Any]:
        return await self.request({"type": "account_list"})

    async def timeline_message_get(
        self,
        account_id_hex: str,
        group_id_hex: str,
        message_id_hex: str,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "timeline_message_get",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "message_id_hex": _normalize_hex(message_id_hex, "message_id_hex"),
            }
        )

    async def timeline_list(
        self,
        account_id_hex: str,
        group_id_hex: str,
        *,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        before_inclusive: bool = False,
        limit: int = 20,
    ) -> Dict[str, Any]:
        def normalize_cursor(cursor: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
            if cursor is None:
                return None
            return {
                "recorded_at": max(0, int(cursor.get("recorded_at") or 0)),
                "message_id_hex": _normalize_hex(
                    cursor.get("message_id_hex"),
                    "timeline cursor message_id_hex",
                ),
            }

        return await self.request(
            {
                "type": "timeline_list",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "before": normalize_cursor(before),
                "after": normalize_cursor(after),
                "before_inclusive": bool(before_inclusive),
                "limit": max(1, min(50, int(limit))),
            }
        )

    async def account_lookup_profile(self, account_id_hex: str) -> Dict[str, Any]:
        response = await self.request(
            {
                "type": "account_profile_lookup",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            }
        )
        status = response.get("status")
        if (
            response.get("type") != "profile_lookup"
            or status not in {"profile_found", "profile_not_found", "indeterminate"}
            or not isinstance(response.get("retryable"), bool)
        ):
            raise AgentControlError("wn-agent returned invalid profile_lookup response", code="protocol_error")
        return response

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
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = idempotency_key.strip() if idempotency_key else None
        payload: Dict[str, Any] = {
            "type": "send_final",
            "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
            "text": str(text or ""),
            "reply_to_message_id_hex": reply_to_message_id_hex,
        }
        # Optional on the wire: only sent when supplied. When present, the
        # connector dedups a retry that reuses the same key instead of
        # double-posting an unrecallable message.
        if key:
            payload["idempotency_key"] = key
        return await self.request(payload)

    async def delete_message(
        self,
        account_id_hex: str,
        group_id_hex: str,
        target_message_id_hex: str,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "delete_message",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "target_message_id_hex": _normalize_hex(
                    target_message_id_hex,
                    "target_message_id_hex",
                ),
            }
        )

    async def send_reaction(
        self,
        account_id_hex: str,
        group_id_hex: str,
        target_message_id_hex: str,
        emoji: str,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "send_reaction",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "target_message_id_hex": _normalize_hex(
                    target_message_id_hex, "target_message_id_hex"
                ),
                "emoji": str(emoji),
            }
        )

    async def remove_reaction(
        self,
        account_id_hex: str,
        group_id_hex: str,
        target_message_id_hex: str,
        emoji: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "type": "remove_reaction",
            "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
            "target_message_id_hex": _normalize_hex(
                target_message_id_hex, "target_message_id_hex"
            ),
        }
        if emoji is not None:
            payload["emoji"] = str(emoji)
        return await self.request(payload)

    async def group_info(self, account_id_hex: str, group_id_hex: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "group_info",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
            }
        )

    async def send_media(
        self,
        account_id_hex: str,
        group_id_hex: str,
        attachments: Iterable[Dict[str, Any]],
        *,
        caption: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        response_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": "send_media",
            "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
            "attachments": list(attachments),
            "caption": str(caption) if caption is not None else None,
        }
        key = str(idempotency_key or "").strip()
        if key:
            payload["idempotency_key"] = key
        # Media upload duration is bounded by connector attachment/byte limits
        # and per-endpoint HTTP deadlines, not by the generic 30-second control
        # timeout. Keep the response wait attached to the one durable operation,
        # but retain a finite ceiling for a connector that never answers. Socket
        # writes remain timed; transport failures retry with the same key.
        completion_timeout = (
            SEND_MEDIA_COMPLETION_TIMEOUT_S
            if response_timeout is None
            else max(0.0, float(response_timeout))
        )
        return await self.request(payload, response_timeout=completion_timeout)

    async def download_media(
        self,
        account_id_hex: str,
        group_id_hex: str,
        media: Dict[str, Any],
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "download_media",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "media": media,
            }
        )

    async def allowlist_list(self, account_id_hex: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "allowlist_list",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            }
        )

    async def allowlist_add(self, account_id_hex: str, welcomer_account_id_hex: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "allowlist_add",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "welcomer_account_id_hex": _normalize_hex(
                    welcomer_account_id_hex,
                    "welcomer_account_id_hex",
                ),
            }
        )

    async def allowlist_remove(self, account_id_hex: str, welcomer_account_id_hex: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "allowlist_remove",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "welcomer_account_id_hex": _normalize_hex(
                    welcomer_account_id_hex,
                    "welcomer_account_id_hex",
                ),
            }
        )

    async def stream_begin(
        self,
        account_id_hex: str,
        group_id_hex: str,
        *,
        stream_id_hex: Optional[str] = None,
        parent_message_id_hex: Optional[str] = None,
        quic_candidates: Iterable[str] = (),
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": "stream_begin",
            "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
            "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
            "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex") if stream_id_hex else None,
            "quic_candidates": [str(candidate).strip() for candidate in quic_candidates if str(candidate).strip()],
        }
        if parent_message_id_hex:
            payload["parent_message_id_hex"] = _normalize_hex(
                parent_message_id_hex,
                "parent_message_id_hex",
            )
        return await self.request(
            payload,
            request_id=request_id,
            timeout=self.preview_request_timeout,
        )

    async def stream_append(
        self,
        stream_id_hex: str,
        stream_capability: str,
        append_text: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = str(idempotency_key or "").strip()
        return await self.request(
            {
                "type": "stream_append",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "stream_capability": _normalize_stream_capability(stream_capability),
                "append_text": str(append_text or ""),
                **({"idempotency_key": key} if key else {}),
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_status(
        self,
        stream_id_hex: str,
        stream_capability: str,
        status: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = str(idempotency_key or "").strip()
        return await self.request(
            {
                "type": "stream_status",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "stream_capability": _normalize_stream_capability(stream_capability),
                "status": str(status or ""),
                **({"idempotency_key": key} if key else {}),
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_progress(
        self,
        stream_id_hex: str,
        stream_capability: str,
        text: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = str(idempotency_key or "").strip()
        return await self.request(
            {
                "type": "stream_progress",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "stream_capability": _normalize_stream_capability(stream_capability),
                "text": str(text or ""),
                **({"idempotency_key": key} if key else {}),
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_finalize(
        self,
        stream_id_hex: str,
        stream_capability: str,
        final_text: str,
        transcript_hash_hex: str,
        chunk_count: int,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = str(idempotency_key or "").strip()
        return await self.request(
            {
                "type": "stream_finalize",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "stream_capability": _normalize_stream_capability(stream_capability),
                "final_text": str(final_text or ""),
                "transcript_hash_hex": _normalize_hex(transcript_hash_hex, "transcript_hash_hex"),
                "chunk_count": int(chunk_count),
                **({"idempotency_key": key} if key else {}),
            }
        )

    async def stream_cancel(
        self,
        stream_id_hex: str,
        stream_capability: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_cancel",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "stream_capability": _normalize_stream_capability(stream_capability),
                "reason": reason,
            },
            timeout=self.preview_request_timeout,
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

    async def _write_envelope(
        self,
        writer: asyncio.StreamWriter,
        payload: Dict[str, Any],
        *,
        request_id: str,
        timeout: Optional[float] = None,
    ) -> None:
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
        write_timeout = self.request_timeout if timeout is None else float(timeout)
        try:
            await asyncio.wait_for(writer.drain(), timeout=write_timeout)
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
            code = str(envelope.get("code") or "agent_control_error")
            retryable = envelope.get("retryable")
            if not isinstance(retryable, bool):
                retryable = code == "send_in_progress"
            raise AgentControlError(
                str(envelope.get("message") or "agent control error"),
                code=code,
                retryable=retryable,
            )



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


def _normalize_stream_capability(value: Any) -> str:
    capability = _normalize_hex(value, "stream_capability")
    if len(capability) != 64:
        raise AgentControlError(
            "stream_capability must encode exactly 32 bytes",
            code="invalid_stream_capability",
        )
    return capability




async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception as exc:
        logger.debug("error while closing Marmot socket writer: %s", exc)

__all__ = [
    "AgentControlError",
    "MarmotAgentControlClient",
    "SEND_MEDIA_COMPLETION_TIMEOUT_S",
]
