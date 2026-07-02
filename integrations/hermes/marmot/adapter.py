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
import mimetypes
import os
import re
import shutil
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Literal, Optional, Tuple

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
AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN = 65519
TEXT_DELTA_RECORD = 0x01
STATUS_RECORD = 0x03
TRANSCRIPT_HASH_CONTEXT = b"marmot agent text stream transcript v1"
STREAM_MESSAGE_PREFIX = "marmot-stream:"
TOOL_PROGRESS_MESSAGE_PREFIX = "marmot-tool-progress:"
TOOL_EVENT_PREFIX = "\x1fMARMOT_TOOL_EVENT:"
# Bounded backoff (seconds) for durable send_final retries. One idempotency key
# is reused across these attempts so a retry after a post-write timeout dedups at
# the connector instead of double-posting. Mirrors OpenClaw dispatch ([100, 300]ms).
SEND_FINAL_RETRY_BACKOFF_S = (0.1, 0.3)
DEFAULT_STREAMING_CURSOR = "\u2589"
_DEFAULT_READ_TIMEOUT = object()
MAX_TOOL_PROGRESS_MESSAGES = 512
DEFAULT_RECONNECT_DELAY_MS = 1000
DEFAULT_MAX_RECONNECT_DELAY_MS = 30_000
DEFAULT_INBOUND_DEDUPE_WINDOW = 2048
DEFAULT_INBOUND_QUEUE_MAX_DEPTH = 32
DEFAULT_AMBIENT_CONTEXT_WINDOW = 2048
DEFAULT_SENT_TARGET_CACHE_SIZE = 2048
DEFAULT_GROUP_ACTIVATION: Literal["mention", "always"] = "mention"
MAX_PROFILE_NAME_CHARS = 80
PROFILE_NAME_PROMPT = (
    "I do not have a public Nostr profile name yet. What should I publish as "
    'this agent\'s display name? Reply with a name, or reply "skip" to stay unnamed.'
)
PROFILE_PROMPT_WITH_NAME = (
    "Hi! I can publish a public Nostr profile so I show up with a name. Want me to "
    'publish it as "{name}"? Reply "yes" to use that, reply with a different name to '
    'use instead, or reply "skip" to stay unnamed.'
)
PROFILE_PROMPT_NO_NAME = (
    "Hi! I can publish a public Nostr profile so I show up with a name. Reply with a "
    'name to publish, or reply "skip" to stay unnamed.'
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
PROFILE_NAME_AFFIRM_REPLIES = {
    "yes",
    "y",
    "yeah",
    "yep",
    "yup",
    "sure",
    "ok",
    "okay",
    "publish",
    "publish it",
    "do it",
    "go ahead",
}
MARMOT_ACCOUNT_ID_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
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


class _ResyncRequired(RuntimeError):
    """Internal signal that the connector dropped inbound messages on broadcast lag and could
    not auto-replay them. Raised out of the inbound consume loop to force a reconnect, which
    re-runs the connector's catch-up and storage-backed replay so the missed messages are
    recovered rather than silently lost."""


class KeyedAsyncQueue:
    """Per-key serialization for fire-and-forget async tasks.

    Mirrors the OpenClaw `KeyedAsyncQueue` (`integrations/openclaw/marmot`): tasks enqueued
    under the same key run strictly FIFO (the next task waits for the prior task of that key
    to finish), while tasks under distinct keys run concurrently. This lets the inbound
    dispatcher hand a slow/hung turn in one group off to the background and keep pulling
    events for other groups instead of blocking head-of-line on every group.

    When ``max_depth_per_key`` is reached for a key, the incoming turn is shed (already-
    queued work is preserved) and ``on_shed`` is invoked with a privacy-safe message.

    `enqueue` is non-blocking: it schedules the work and returns immediately. Use `join` to
    wait for all currently scheduled work to drain (chiefly for tests and clean shutdown) and
    `cancel_all` to tear everything down.
    """

    def __init__(
        self,
        max_depth_per_key: int = DEFAULT_INBOUND_QUEUE_MAX_DEPTH,
        on_shed: Optional[Any] = None,
    ) -> None:
        self._max_depth_per_key = max(1, int(max_depth_per_key))
        self._on_shed = on_shed
        # Most-recently-enqueued task per key; the chain tail each new same-key task awaits.
        self._tails: Dict[Any, asyncio.Task] = {}
        # Every in-flight task, so join()/cancel_all() can act on the whole queue.
        self._pending: set[asyncio.Task] = set()
        self._queued_depth: Dict[Any, int] = {}

    def enqueue(self, key: Any, coro_factory) -> Optional[asyncio.Task]:
        """Schedule ``coro_factory()`` to run after any prior task for ``key`` completes.

        ``coro_factory`` is a zero-arg callable returning a coroutine; it is only invoked when
        the task actually starts, so per-key ordering is preserved without eagerly creating
        coroutines that might warn if never awaited.

        Returns ``None`` when the per-key depth cap is reached and the turn is shed.
        """

        depth = self._queued_depth.get(key, 0)
        if depth >= self._max_depth_per_key:
            if self._on_shed:
                self._on_shed("Marmot inbound queue depth exceeded; shedding turn")
            else:
                logger.warning("Marmot inbound queue depth exceeded; shedding turn")
            return None

        self._queued_depth[key] = depth + 1
        predecessor = self._tails.get(key)

        async def _runner() -> None:
            try:
                if predecessor is not None:
                    # Wait for the prior same-key task, but never inherit its failure/cancellation:
                    # one group's bad turn must not poison the next message in that group.
                    try:
                        await asyncio.shield(predecessor)
                    except BaseException:
                        pass
                await coro_factory()
            finally:
                remaining = max(0, self._queued_depth.get(key, 1) - 1)
                if remaining == 0:
                    self._queued_depth.pop(key, None)
                else:
                    self._queued_depth[key] = remaining

        task = asyncio.ensure_future(_runner())
        self._tails[key] = task
        self._pending.add(task)

        def _done(completed: asyncio.Task, _key=key) -> None:
            self._pending.discard(completed)
            # Only clear the tail if we are still the latest task for this key; a newer
            # enqueue may have already replaced us as the chain tail.
            if self._tails.get(_key) is completed:
                self._tails.pop(_key, None)

        task.add_done_callback(_done)
        return task

    async def join(self) -> None:
        """Wait until all currently scheduled tasks (and any they chain to) have finished."""
        while self._pending:
            await asyncio.gather(*list(self._pending), return_exceptions=True)

    async def cancel_all(self) -> None:
        """Cancel every in-flight task and wait for them to unwind."""
        pending = list(self._pending)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._pending.clear()
        self._tails.clear()
        self._queued_depth.clear()


class _RecentKeys:
    """Bounded, insertion-ordered set for recent-id/-context dedupe.

    Mirrors the OpenClaw ``RecentIds`` (inbound.ts): FIFO eviction once the
    window is exceeded so a long-running subscription cannot grow unbounded.
    """

    def __init__(self, max_size: int):
        self.max_size = int(max_size)
        self._keys: "OrderedDict[str, None]" = OrderedDict()

    def __contains__(self, key: str) -> bool:
        return key in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def add(self, key: str) -> None:
        self._keys[key] = None
        while len(self._keys) > self.max_size:
            self._keys.popitem(last=False)


class SentMessageTargetCache:
    """Maps durable message ids to the account+group they were sent to.

    Mirrors OpenClaw ``SentMessageTargetCache`` so a later delete can be routed
    without an extra round-trip.
    """

    def __init__(self, max_size: int = DEFAULT_SENT_TARGET_CACHE_SIZE) -> None:
        self.max_size = int(max_size)
        self._entries: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()

    def record(self, message_id_hex: str, *, account_id_hex: str, group_id_hex: str) -> None:
        message_id_hex = _normalize_hex(message_id_hex, "message_id_hex")
        account_id_hex = _normalize_hex(account_id_hex, "account_id_hex")
        group_id_hex = _normalize_hex(group_id_hex, "group_id_hex")
        if message_id_hex in self._entries:
            self._entries.pop(message_id_hex, None)
        self._entries[message_id_hex] = (account_id_hex, group_id_hex)
        while len(self._entries) > self.max_size:
            self._entries.popitem(last=False)

    def record_all(
        self,
        message_ids_hex: Iterable[str],
        *,
        account_id_hex: str,
        group_id_hex: str,
    ) -> None:
        for message_id_hex in message_ids_hex:
            self.record(
                message_id_hex,
                account_id_hex=account_id_hex,
                group_id_hex=group_id_hex,
            )

    def lookup(self, message_id_hex: str) -> Optional[Tuple[str, str]]:
        return self._entries.get(_normalize_hex(message_id_hex, "message_id_hex"))


class GroupActivationCache:
    """Per-(account, group) cache of the ``is_direct`` activation fact."""

    def __init__(self) -> None:
        self._is_direct: Dict[str, bool] = {}

    @staticmethod
    def _key(account_id_hex: str, group_id_hex: str) -> str:
        return f"{account_id_hex}:{group_id_hex}"

    def get(self, account_id_hex: str, group_id_hex: str) -> Optional[bool]:
        return self._is_direct.get(self._key(account_id_hex, group_id_hex))

    def set(self, account_id_hex: str, group_id_hex: str, is_direct: bool) -> None:
        self._is_direct[self._key(account_id_hex, group_id_hex)] = bool(is_direct)

    def invalidate(self, account_id_hex: str, group_id_hex: str) -> None:
        self._is_direct.pop(self._key(account_id_hex, group_id_hex), None)

    def clear(self) -> None:
        self._is_direct.clear()


def matches_mention_pattern(text: str, patterns: Iterable[str]) -> bool:
    haystack = str(text or "").lower()
    for pattern in patterns:
        needle = str(pattern or "").strip().lower()
        if needle and needle in haystack:
            return True
    return False


def _coalesce_inbound_events(items: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge a debounce batch of same-key inbound events into one (mirrors
    inbound-runtime.ts ``coalesceInboundMessages``).

    Keeps the LAST event's ids (message_id, reply_to, sender) as the
    representative, but carries merged text/mentions/media:
    - text: newline-joined, skipping empty parts;
    - ``mentions_self``: OR across the batch (true if ANY message mentions self);
    - ``media``: deduped by ``ciphertext_sha256`` across the batch;
    - ``reply_to_message_id_hex``: newest non-null value in the batch.
    """
    last = items[-1]
    if len(items) == 1:
        return last

    merged = dict(last)
    text_parts = [str(item.get("text") or "") for item in items]
    merged["text"] = "\n".join(part for part in text_parts if part)
    merged["mentions_self"] = any(bool(item.get("mentions_self")) for item in items)
    media: list[Any] = []
    media_hashes: set[str] = set()
    for item in items:
        item_media = item.get("media")
        if not isinstance(item_media, (list, tuple)):
            continue
        for ref in item_media:
            if not isinstance(ref, dict):
                continue
            digest = str(ref.get("ciphertext_sha256") or "").strip().lower()
            if digest and digest in media_hashes:
                continue
            if digest:
                media_hashes.add(digest)
            media.append(ref)
    if media:
        merged["media"] = media
    reply_to = None
    for item in reversed(items):
        candidate = item.get("reply_to_message_id_hex")
        if candidate:
            reply_to = candidate
            break
    if reply_to:
        merged["reply_to_message_id_hex"] = reply_to
    return merged


def reconnect_backoff_ms(
    attempt: int,
    base_ms: float,
    cap_ms: float,
    rand: Any = None,
) -> float:
    """Reconnect backoff with jitter: a delay in
    ``[base_ms, min(cap_ms, base_ms * 2**attempt)]``.

    Faithful port of inbound.ts ``reconnectBackoffMs`` (lines 87-101): attempt 0
    returns exactly ``base_ms`` (ceiling == base) so the first reconnect is as
    prompt as the old flat delay; later attempts grow geometrically toward the
    cap. The jitter spreads retries so a persistent failure does not spin at a
    fixed cadence. ``rand`` defaults to :func:`random.random` and may be injected
    for deterministic tests.
    """
    if base_ms <= 0:
        return 0
    if rand is None:
        import random

        rand = random.random
    ceiling = min(cap_ms, base_ms * 2 ** max(0, attempt))
    if ceiling <= base_ms:
        return base_ms
    return round(base_ms + rand() * (ceiling - base_ms))


def group_state_change_sentence(change: str, detail: Optional[str] = None) -> str:
    """Map a coarse group-state change kind to a short, privacy-safe sentence
    for ambient agent context. NEVER includes a member pubkey; the only detail
    surfaced is the new group name on a rename (mirrors inbound-runtime.ts
    ``groupStateChangeSentence`` lines 62-83)."""
    if change == "member_added":
        return "A member was added to the group."
    if change == "member_removed":
        return "A member was removed from the group."
    if change == "member_left":
        return "A member left the group."
    if change == "admin_added":
        return "A member was made a group admin."
    if change == "admin_removed":
        return "A member is no longer a group admin."
    if change == "group_renamed":
        trimmed = str(detail or "").strip()
        return f'The group was renamed to "{trimmed}".' if trimmed else "The group was renamed."
    if change == "group_avatar_changed":
        return "The group avatar was changed."
    return "The group state changed."


def normalize_welcomer_id(entry: str | int) -> str:
    return str(entry).strip().lower().removeprefix("0x")


async def sync_allowlist(
    client: MarmotAgentControlClient,
    account_id_hex: str,
    desired: Iterable[str | int],
) -> Dict[str, list[str]]:
    """Reconcile dm-agent's welcomer allowlist to exactly ``desired`` hex ids."""
    want = {
        normalize_welcomer_id(entry)
        for entry in desired
        if MARMOT_ACCOUNT_ID_HEX_RE.fullmatch(normalize_welcomer_id(entry))
    }
    current = await client.allowlist_list(account_id_hex)
    have = {
        normalize_welcomer_id(entry)
        for entry in (current.get("welcomer_account_ids_hex") or [])
        if MARMOT_ACCOUNT_ID_HEX_RE.fullmatch(normalize_welcomer_id(entry))
    }

    added: list[str] = []
    removed: list[str] = []
    for entry in want:
        if entry not in have:
            await client.allowlist_add(account_id_hex, entry)
            added.append(entry)
    for entry in have:
        if entry not in want:
            await client.allowlist_remove(account_id_hex, entry)
            removed.append(entry)
    return {"added": added, "removed": removed}


def resolve_marmot_home(extra: Dict[str, Any], socket_path: str | Path) -> Path:
    home = _first_config_value(extra, "home", "marmot_home", env="MARMOT_HOME")
    if home:
        return Path(str(home)).expanduser()
    return Path(socket_path).expanduser().parent.parent


def resolve_inbound_media_dir(extra: Dict[str, Any], socket_path: str | Path) -> Path:
    configured = _first_config_value(extra, "inbound_media_dir", env="MARMOT_INBOUND_MEDIA_DIR")
    if configured:
        return Path(str(configured)).expanduser()
    return resolve_marmot_home(extra, socket_path) / "dev" / "inbound-media"


def resolve_allowed_media_roots(extra: Dict[str, Any], socket_path: str | Path) -> list[Path]:
    configured = extra.get("media_local_roots")
    if configured is None:
        configured = extra.get("mediaLocalRoots")
    if configured is None:
        configured = os.getenv("MARMOT_MEDIA_LOCAL_ROOTS")
    if configured is not None:
        return [Path(entry).expanduser() for entry in _split_config_list(configured)]
    return [resolve_inbound_media_dir(extra, socket_path)]


def resolve_welcomer_allowlist(extra: Dict[str, Any]) -> list[str]:
    for key in ("welcomer_allowlist", "welcomerAllowlist", "dm_allow_from", "dmAllowFrom"):
        if key in extra:
            return _split_config_list(extra[key])
    configured = os.getenv("MARMOT_WELCOMER_ALLOWLIST") or os.getenv("MARMOT_DM_ALLOW_FROM")
    return _split_config_list(configured) if configured else []


def path_is_under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def assert_local_media_allowed(path: Path, allowed_roots: list[Path]) -> None:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise AgentControlError("Marmot media path is not a readable file")
    if not allowed_roots:
        raise AgentControlError("Marmot media path is outside allowed local roots")
    if any(path_is_under_root(resolved, root) for root in allowed_roots):
        return
    raise AgentControlError("Marmot media path is outside allowed local roots")


def valid_profile_name(name: Any) -> Optional[str]:
    value = " ".join(str(name or "").split())
    if not value or len(value) > MAX_PROFILE_NAME_CHARS:
        return None
    return value


def build_profile_prompt(suggested_name: Optional[str]) -> str:
    if suggested_name:
        return PROFILE_PROMPT_WITH_NAME.format(name=suggested_name)
    return PROFILE_PROMPT_NO_NAME


class AppendOnlyTextState:
    """Tracks the latest visible stream text and returns safe suffix deltas."""

    def __init__(self):
        self.text = ""

    def pending_suffix_for(self, next_text: str) -> str:
        """Validate that ``next_text`` extends the current text and return the
        append-only suffix WITHOUT advancing ``self.text``. The caller commits
        the advance with :meth:`commit` only after the remote append succeeds, so
        a failed append can be retried with the same text without diverging from
        the connector's transcript (mirrors live.ts ``update()``)."""
        next_text = str(next_text or "")
        if not next_text.startswith(self.text):
            raise NonAppendOnlyUpdate("Marmot stream update is not append-only")
        return next_text[len(self.text):]

    def commit(self, next_text: str) -> None:
        self.text = str(next_text or "")

    def suffix_for(self, next_text: str) -> str:
        suffix = self.pending_suffix_for(next_text)
        self.commit(next_text)
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

    async def try_claim_prompt(
        self,
        account_id_hex: str,
        group_id_hex: str,
        suggested_name: Optional[str] = None,
    ) -> bool:
        """Atomically claim the one-time prompt slot for ``account_id_hex``.

        Mirrors OpenClaw's ``tryClaimPrompt`` (``integrations/openclaw/marmot/src/
        profile-onboarding.ts``). The read-decide-write happens under a SINGLE lock
        acquisition, so two first messages racing across concurrent groups (now that
        inbound dispatch is per-group concurrent, #513) cannot both observe empty state
        and both send a prompt. Returns True only for the caller that won the claim and
        should therefore send the prompt; every later caller gets False. If sending the
        prompt then fails, the winner must ``clear()`` the slot so a later message retries.
        """
        async with self._lock:
            data = self._read()
            accounts = data.setdefault("accounts", {})
            existing = accounts.get(account_id_hex) or {}
            if existing.get("status"):
                return False
            accounts[account_id_hex] = {
                "status": "prompted",
                "group_id_hex": group_id_hex,
                **({"suggested_name": suggested_name} if suggested_name else {}),
            }
            self._write(data)
            return True

    async def clear(self, account_id_hex: str) -> None:
        """Reset an account's record so the prompt can be retried (e.g. after a send failure)."""
        async with self._lock:
            data = self._read()
            accounts = data.setdefault("accounts", {})
            if account_id_hex in accounts:
                accounts.pop(account_id_hex, None)
                self._write(data)

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
    ) -> Dict[str, Any]:
        request_id = request_id or uuid.uuid4().hex
        effective_timeout = self.request_timeout if timeout is None else float(timeout)
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._write_envelope(writer, payload, request_id=request_id, timeout=effective_timeout)
            response = await self._read_envelope(reader, timeout=effective_timeout)
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
        # Additive, v1-compatible: only sent when supplied so an old connector's
        # frame stays unchanged. When present, the connector dedups a retry that
        # reuses the same key instead of double-posting an unrecallable message.
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
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "send_media",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "attachments": list(attachments),
                "caption": str(caption) if caption is not None else None,
            }
        )

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
        quic_candidates: Iterable[str] = (),
    ) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_begin",
                "account_id_hex": _normalize_hex(account_id_hex, "account_id_hex"),
                "group_id_hex": _normalize_hex(group_id_hex, "group_id_hex"),
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex") if stream_id_hex else None,
                "quic_candidates": [str(candidate).strip() for candidate in quic_candidates if str(candidate).strip()],
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_append(self, stream_id_hex: str, append_text: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_append",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "append_text": str(append_text or ""),
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_status(self, stream_id_hex: str, status: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_status",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "status": str(status or ""),
            },
            timeout=self.preview_request_timeout,
        )

    async def stream_progress(self, stream_id_hex: str, text: str) -> Dict[str, Any]:
        return await self.request(
            {
                "type": "stream_progress",
                "stream_id_hex": _normalize_hex(stream_id_hex, "stream_id_hex"),
                "text": str(text or ""),
            },
            timeout=self.preview_request_timeout,
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
            chunk_bytes=effective_stream_chunk_bytes(
                chunk_bytes,
                response.get("policy_max_plaintext_frame_len"),
            ),
        )

    async def append_replacement(self, next_text: str) -> None:
        next_text = str(next_text or "")
        suffix = self.text.pending_suffix_for(next_text)
        if not suffix:
            return
        # Commit local transcript/append-only state only AFTER the remote append
        # succeeds, so a failed append leaves the stream consistent and the same
        # text re-appendable (mirrors live.ts update() lines 99-116).
        await self.client.stream_append(self.stream_id_hex, suffix)
        self.transcript.append_text(suffix)
        self.text.commit(next_text)

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
        self.debounce_ms = resolve_debounce_ms(extra)
        self.group_activation = resolve_group_activation(extra)
        self.mention_patterns = resolve_mention_patterns(extra)
        self.agent_name = _first_config_value(extra, "agent_name", "agentName", env="MARMOT_AGENT_NAME")
        self.welcomer_allowlist = resolve_welcomer_allowlist(extra)
        self._allowed_media_roots = resolve_allowed_media_roots(extra, self.socket_path)
        self._inbound_media_dir = resolve_inbound_media_dir(extra, self.socket_path)
        self.profile_name_onboarding_enabled = resolve_profile_name_onboarding_enabled(extra)
        self.profile_name_onboarding = (
            ProfileNameOnboardingStore(resolve_profile_onboarding_state_path(extra, self.socket_path))
            if self.profile_name_onboarding_enabled
            else None
        )
        self._sent_targets = SentMessageTargetCache()
        self._activation_cache = GroupActivationCache()
        self._listener_task: Optional[asyncio.Task] = None
        self._inbound_queue = KeyedAsyncQueue()
        self._active_streams: Dict[str, MarmotLiveStream] = {}
        self._draft_streams: Dict[tuple[str, int], MarmotLiveStream] = {}
        self._last_chat_stream: Dict[str, MarmotLiveStream] = {}
        self._tool_progress_events: OrderedDict[str, set[str]] = OrderedDict()
        self._tool_progress_replies: Dict[str, Optional[str]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Client-side inbound dedupe: dm-agent can re-emit the same inbound
        # message (rapid catch-up after subscribe, or across a reconnect); drop
        # ids already seen so the same user message is not dispatched twice.
        self._recent_inbound_ids = _RecentKeys(DEFAULT_INBOUND_DEDUPE_WINDOW)
        # Dedupe repeated ambient surfacings (deletion / group-state change) by a
        # context key (mirror inbound.ts contextKeys).
        self._recent_ambient_keys = _RecentKeys(DEFAULT_AMBIENT_CONTEXT_WINDOW)
        # Pending quiet next-turn ambient context, keyed by group id. Ambient
        # events (a deletion, a group-state change) are NOT reply triggers: they
        # are buffered here and prepended to the next real inbound message for
        # that group as channel_context, so the agent sees the fact on its next
        # turn without an ambient event spuriously starting an agent turn of its
        # own. Mirrors OpenClaw's quiet-next-turn surfacer (inbound-runtime.ts);
        # when no message follows, the fact is only logged (also OpenClaw parity).
        self._pending_ambient_context: Dict[str, list[str]] = {}
        # Optional inbound debounce: coalesce rapid same-(account,group,sender)
        # bursts into one turn. Disabled when debounce_ms <= 0.
        self._debounce_pending: Dict[str, list[Dict[str, Any]]] = {}
        self._debounce_tasks: Dict[str, asyncio.Task] = {}
        # Set true once the current subscription yields/acks (healthy); used by
        # the reconnect-backoff loop to reset its attempt counter.
        self._inbound_established = False

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
            await self._sync_welcomer_allowlist()
            self._listener_task = asyncio.create_task(self._consume_inbound_loop())
            self._mark_connected()
            return True
        except Exception as exc:
            logger.error("Failed to connect Marmot adapter: %s", exc)
            set_fatal = getattr(self, "_set_fatal_error", None)
            if callable(set_fatal):
                set_fatal("marmot_connect_failed", str(exc), retryable=True)
            return False

    async def _sync_welcomer_allowlist(self) -> None:
        if not self.welcomer_allowlist:
            return
        try:
            account_id = await self._ensure_account_id()
            result = await sync_allowlist(self.client, account_id, self.welcomer_allowlist)
            logger.debug(
                "Marmot welcomer allowlist synced (added=%d removed=%d)",
                len(result["added"]),
                len(result["removed"]),
            )
        except Exception:
            logger.debug("Marmot welcomer allowlist sync failed", exc_info=True)

    async def disconnect(self) -> None:
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        await self._inbound_queue.cancel_all()
        await self._cancel_all_streams("adapter disconnect")
        self._cancel_debounce_tasks()
        self._pending_ambient_context.clear()
        self._activation_cache.clear()
        self._tool_progress_events.clear()
        self._tool_progress_replies.clear()
        self._mark_disconnected()

    def _cancel_debounce_tasks(self) -> None:
        for task in self._debounce_tasks.values():
            if not task.done():
                task.cancel()
        self._debounce_tasks.clear()
        self._debounce_pending.clear()

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
                return await self._abandon_preview_and_send_final(
                    chat_id,
                    stream,
                    visible_content,
                    message_id=message_id,
                    reason="final text was not append-only",
                    reply_to_message_id_hex=_optional_hex(reply_to),
                )
            except Exception as exc:
                logger.debug("Marmot live-preview finalize failed: %s", exc)
                return await self._abandon_preview_and_send_final(
                    chat_id,
                    stream,
                    visible_content,
                    message_id=message_id,
                    reason="finalize_error",
                    reply_to_message_id_hex=_optional_hex(reply_to),
                )

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
            if finalize:
                return await self._abandon_preview_and_send_final(
                    chat_id,
                    stream,
                    visible_content,
                    message_id=message_id,
                    reason=str(exc),
                )
            await self._cancel_stream(chat_id, message_id, stream, str(exc))
            return SendResult(success=False, error=str(exc), retryable=False)
        except Exception as exc:
            logger.debug("Marmot live-preview edit failed: %s", exc)
            if finalize:
                return await self._abandon_preview_and_send_final(
                    chat_id,
                    stream,
                    visible_content,
                    message_id=message_id,
                    reason="finalize_error",
                )
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
        try:
            result = self._result_from_stream_finalize(response)
        except Exception as exc:
            logger.debug("Marmot stream finalize response rejected: %s", exc)
            await self._cancel_stream(chat_id, message_id, stream, "finalize rejected")
            return await self._send_final_direct(chat_id, final_text)
        account_id = await self._ensure_account_id()
        self._sent_targets.record_all(
            tuple(response.get("message_ids_hex") or ()),
            account_id_hex=account_id,
            group_id_hex=chat_id,
        )
        return result

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

    async def _abandon_preview_and_send_final(
        self,
        chat_id: str,
        stream: MarmotLiveStream,
        final_text: str,
        *,
        message_id: Optional[str] = None,
        reason: str,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> SendResult:
        await self._cancel_stream(chat_id, message_id, stream, reason)
        return await self._send_final_direct(
            chat_id,
            final_text,
            reply_to_message_id_hex=reply_to_message_id_hex,
        )

    async def _send_final_direct(
        self,
        chat_id: str,
        content: str,
        *,
        reply_to_message_id_hex: Optional[str] = None,
    ) -> SendResult:
        # One idempotency key for every attempt of THIS durable reply: a retry
        # after a post-write timeout reuses the key so the connector dedups
        # instead of double-posting an unrecallable encrypted message. Bounded
        # retries with a tiny backoff cover the transient/timeout window;
        # non-retryable errors fail fast. Mirrors OpenClaw dispatch.ts.
        idempotency_key = uuid.uuid4().hex
        last_exc: BaseException | None = None
        for attempt in range(len(SEND_FINAL_RETRY_BACKOFF_S) + 1):
            try:
                account_id = await self._ensure_account_id()
                response = await self.client.send_final(
                    account_id,
                    chat_id,
                    content,
                    reply_to_message_id_hex=reply_to_message_id_hex,
                    idempotency_key=idempotency_key,
                )
                message_ids = tuple(response.get("message_ids_hex") or ())
                message_id = message_ids[-1] if message_ids else None
                self._sent_targets.record_all(
                    message_ids,
                    account_id_hex=account_id,
                    group_id_hex=chat_id,
                )
                return SendResult(
                    success=True,
                    message_id=message_id,
                    raw_response=response,
                    continuation_message_ids=message_ids[:-1],
                )
            except Exception as exc:
                last_exc = exc
                if attempt < len(SEND_FINAL_RETRY_BACKOFF_S) and is_retryable(exc):
                    logger.debug(
                        "Marmot send_final failed; retrying (attempt %d): %s",
                        attempt + 1,
                        exc,
                    )
                    await asyncio.sleep(SEND_FINAL_RETRY_BACKOFF_S[attempt])
                    continue
                logger.debug("Marmot send_final failed: %s", exc)
                return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))
        # Unreachable: the loop returns on success or on the final attempt.
        return SendResult(
            success=False,
            error=str(last_exc) if last_exc else "Marmot send_final failed",
            retryable=is_retryable(last_exc) if last_exc else False,
        )

    async def _send_media_upload(
        self,
        chat_id: str,
        *,
        path: str,
        media_type: str,
        file_name: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> SendResult:
        if reply_to:
            return SendResult(
                success=False,
                error="Marmot media sends do not support reply threading yet",
            )

        local_path = Path(str(path)).expanduser()
        try:
            assert_local_media_allowed(local_path, self._allowed_media_roots)
        except AgentControlError as exc:
            return SendResult(success=False, error=str(exc))

        account_id = await self._ensure_account_id()
        chat_id = _normalize_hex(chat_id, "chat_id")
        try:
            response = await self.client.send_media(
                account_id,
                chat_id,
                [
                    {
                        "path": str(local_path),
                        "media_type": str(media_type or "application/octet-stream"),
                        "file_name": str(file_name or local_path.name or "attachment"),
                    }
                ],
                caption=caption,
            )
        except Exception as exc:
            logger.debug("Marmot send_media failed: %s", exc)
            return SendResult(success=False, error=str(exc), retryable=is_retryable(exc))

        message_ids = tuple(response.get("message_ids_hex") or ())
        message_id = message_ids[-1] if message_ids else None
        self._sent_targets.record_all(
            message_ids,
            account_id_hex=account_id,
            group_id_hex=chat_id,
        )
        return SendResult(
            success=True,
            message_id=message_id,
            raw_response=response,
            continuation_message_ids=message_ids[:-1],
        )

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        path = Path(str(image_path)).expanduser()
        media_type = mimetypes.guess_type(path.name)[0] or "image/jpeg"
        return await self._send_media_upload(
            chat_id,
            path=str(path),
            media_type=media_type,
            file_name=path.name,
            caption=caption,
            reply_to=reply_to,
        )

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        path = Path(str(file_path)).expanduser()
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return await self._send_media_upload(
            chat_id,
            path=str(path),
            media_type=media_type,
            file_name=path.name,
            caption=caption,
            reply_to=reply_to,
        )

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        path = Path(str(video_path)).expanduser()
        media_type = mimetypes.guess_type(path.name)[0] or "video/mp4"
        return await self._send_media_upload(
            chat_id,
            path=str(path),
            media_type=media_type,
            file_name=path.name,
            caption=caption,
            reply_to=reply_to,
        )

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        **kwargs: Any,
    ) -> SendResult:
        path = Path(str(audio_path)).expanduser()
        media_type = mimetypes.guess_type(path.name)[0] or "audio/mpeg"
        return await self._send_media_upload(
            chat_id,
            path=str(path),
            media_type=media_type,
            file_name=path.name,
            caption=kwargs.get("caption"),
            reply_to=kwargs.get("reply_to"),
        )

    async def delete_message(self, chat_id: str, message_id: str) -> bool:
        target = self._sent_targets.lookup(message_id)
        account_id: Optional[str]
        group_id: Optional[str]
        if target is not None:
            account_id, group_id = target
        else:
            account_id = self.account_id_hex or None
            group_id = _optional_hex(chat_id, "chat_id")
            if account_id is None or group_id is None:
                return False
        try:
            account_id = account_id or await self._ensure_account_id()
            await self.client.delete_message(account_id, group_id, message_id)
            return True
        except Exception as exc:
            logger.debug("Marmot delete_message failed: %s", exc)
            return False

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
        signing_accounts = [account for account in accounts if account.get("local_signing")]
        if len(signing_accounts) == 1:
            self.account_id_hex = _normalize_hex(signing_accounts[0]["account_id_hex"], "account_id_hex")
            return self.account_id_hex
        if not signing_accounts:
            raise AgentControlError(
                "dm-agent has no local-signing Marmot account; run `dm-agent bootstrap` first",
                code="no_accounts",
            )
        raise AgentControlError(
            "dm-agent hosts multiple local-signing accounts; set MARMOT_ACCOUNT_ID_HEX",
            code="ambiguous_account",
        )

    async def _consume_inbound_loop(self, *, rand: Any = None) -> None:
        base_ms = float(DEFAULT_RECONNECT_DELAY_MS)
        cap_ms = float(DEFAULT_MAX_RECONNECT_DELAY_MS)
        # Clamp the base to the cap so the delay never goes above the cap when a
        # ceiling collapses to the base (mirrors inbound.ts line 157).
        effective_base_ms = min(base_ms, cap_ms)
        # Consecutive reconnect attempts that have not (re)established a healthy
        # subscription. Reset to 0 once a subscription yields/acks so a healthy
        # connection always reconnects promptly, while a persistent failure backs
        # off geometrically instead of spinning at a flat cadence.
        attempt = 0
        while True:
            try:
                await self._consume_inbound_once(on_established=lambda: None)
            except asyncio.CancelledError:
                raise
            except _ResyncRequired as exc:
                # The connector could not auto-replay the messages dropped on broadcast lag and
                # asked us to re-sync. Tear down and reopen the subscription: a fresh subscription
                # re-runs the connector's catch_up_accounts() and a fresh storage-backed replay,
                # which recovers the missed inbound messages we would otherwise never see. A
                # resync is just another reconnect reason and uses the same backoff.
                logger.warning("Marmot inbound resync requested, reconnecting: %s", exc)
            except Exception as exc:
                logger.warning("Marmot inbound subscription failed, retrying: %s", exc)
            else:
                # A clean return means the subscription was dropped (the connector
                # closed the inbound stream with a normal EOF rather than an error).
                # That is still a reconnect, NOT a success: fall through to the same
                # backoff path as an error so a socket that accepts-acks-then-closes
                # cannot pin us in a hot resubscribe loop (mirrors OpenClaw's
                # MarmotInboundBridge.run(), which backs off after stream completion
                # too). The _inbound_established check below keeps an established-then-
                # idle subscription reconnecting promptly.
                logger.debug("Marmot inbound subscription closed cleanly, reconnecting")
            # Reset the attempt counter whenever the subscription was healthy
            # (it established and yielded/acked at least once) so the next failure
            # starts the backoff fresh; a subscription that never established (e.g.
            # an immediate clean EOF) backs off geometrically instead of spinning.
            if self._inbound_established:
                attempt = 0
            delay_ms = reconnect_backoff_ms(attempt, effective_base_ms, cap_ms, rand=rand)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000)
            attempt += 1

    async def _consume_inbound_once(self, *, drain: bool = False, on_established: Any = None) -> None:
        # Per-group serialization (mirrors OpenClaw's KeyedAsyncQueue): a slow/hung turn in one
        # group must not block inbound dispatch for every other group. We enqueue each inbound
        # message onto a per-group FIFO queue and keep pulling events instead of awaiting the
        # turn inline.
        #
        # The queue is a single long-lived instance owned by the adapter (constructed in
        # __init__, torn down by disconnect -> cancel_all). It MUST survive subscription
        # end/error: a resync tears the stream down and _consume_inbound_loop() reopens it, so
        # joining the queue here would let a hung group-A turn hold the resync (and therefore
        # every later group) hostage — the exact head-of-line blocking #513 fixes. So production
        # never drains on stream end; only an explicit shutdown (cancel_all) or a test asking to
        # observe completion (drain=True) waits on in-flight work.
        self._inbound_established = False
        try:
            async for event in self.client.inbound_events(
                account_id_hex=self.account_id_hex,
                group_id_hex=self.group_id_hex,
            ):
                # A yielded event means the subscription was acked and is healthy;
                # mark it established so the reconnect loop resets its backoff
                # attempt counter (a healthy-then-dropped subscription reconnects
                # promptly; one that never establishes backs off geometrically).
                if not self._inbound_established:
                    self._inbound_established = True
                    if callable(on_established):
                        on_established()
                await self._handle_control_event(event)
        finally:
            if drain:
                await self._inbound_queue.join()

    async def _handle_resync_required(self, event: Dict[str, Any]) -> None:
        # Emitted when the connector's inbound broadcast lagged AND its storage-backed replay
        # could not recover the dropped messages. We must not silently drop user messages: force a
        # reconnect so the connector re-runs catch-up and replays from storage on a fresh
        # subscription. Privacy-safe log: counts only, never ids/payloads.
        dropped_events = event.get("dropped_events")
        logger.warning(
            "Marmot connector requested resync (dropped_events=%s); reconnecting subscription",
            dropped_events,
        )
        self._activation_cache.clear()
        raise _ResyncRequired(
            f"connector resync_required (dropped_events={dropped_events})"
        )

    async def _handle_control_event(self, event: Dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "resync_required":
            await self._handle_resync_required(event)
            return
        if event_type == "message_deleted":
            await self._handle_message_deleted(event)
            return
        if event_type == "group_state_changed":
            await self._handle_group_state_changed(event)
            return
        if event_type == "group_invite":
            await self._handle_group_invite(event)
            return
        if event_type != "inbound_message":
            logger.debug("Ignoring Marmot control event type %s", event_type)
            return

        message_id_hex = event["message_id_hex"]
        # Client-side dedupe: the connector can re-emit the same inbound message
        # (rapid catch-up after subscribe, or across a reconnect). Drop a repeat
        # silently so the same user message is not dispatched twice. Record the id
        # BEFORE dispatching (an agent turn takes long enough that record-after
        # would let a duplicate start a second concurrent turn). Dedupe the id
        # once regardless of whether onboarding intercepts the message.
        if message_id_hex in self._recent_inbound_ids:
            return
        self._recent_inbound_ids.add(message_id_hex)

        if self.debounce_ms > 0:
            self._enqueue_debounced(event)
            return

        # Hand the turn off to the per-group queue and return immediately so the consume loop
        # keeps pulling events. Distinct groups dispatch concurrently; each group stays FIFO.
        group_id_hex = event["group_id_hex"]
        self._inbound_queue.enqueue(
            group_id_hex,
            lambda evt=event: self._dispatch_inbound_message(evt),
        )

    async def _handle_group_invite(self, event: Dict[str, Any]) -> None:
        if not self.profile_name_onboarding_enabled or self.profile_name_onboarding is None:
            return
        try:
            account_id_hex = _normalize_hex(event["account_id_hex"], "account_id_hex")
            group_id_hex = _normalize_hex(event["group_id_hex"], "group_id_hex")
        except Exception:
            logger.debug("Ignoring Marmot group_invite with missing ids")
            return
        self._inbound_queue.enqueue(
            group_id_hex,
            lambda: self._maybe_send_profile_prompt_on_join(account_id_hex, group_id_hex),
        )

    async def _dispatch_inbound_message(self, event: Dict[str, Any]) -> None:
        try:
            group_id_hex = event["group_id_hex"]
            sender_account_id_hex = event["sender_account_id_hex"]
            message_id_hex = event["message_id_hex"]
            if not await self._should_run_turn(event):
                logger.debug("Marmot inbound not addressed; skipping turn (groupActivation=mention)")
                return
            # Profile-name onboarding runs inside the queued (per-group) unit so the
            # one-time prompt claim is serialized per group: two concurrent first
            # messages in distinct groups race only across groups, and the loser of
            # the claim falls through to a normal turn instead of double-prompting.
            if await self._maybe_handle_profile_name_onboarding(event):
                return

            sender_display_name = str(event.get("sender_display_name") or "").strip()
            user_name = sender_display_name or f"Marmot {sender_account_id_hex[:12]}"

            source = self.build_source(
                chat_id=group_id_hex,
                chat_name=f"Marmot {group_id_hex[:12]}",
                chat_type="group",
                user_id=sender_account_id_hex,
                user_name=user_name,
                # The durable reply threads on source.message_id, so set it to the
                # inbound message id: the agent's reply threads to the message it is
                # replying to (mirrors dispatch.ts replyToMessageIdHex = inbound id).
                message_id=message_id_hex,
            )
            hermes_event = MessageEvent(
                text=str(event.get("text") or ""),
                message_type=MessageType.TEXT,
                source=source,
                raw_message=event,
                message_id=message_id_hex,
            )
            media_urls, media_types = await self._download_inbound_media(event)
            if media_urls:
                hermes_event.media_urls = media_urls
                hermes_event.media_types = media_types
            # Attach any buffered quiet ambient context (a deletion / group-state
            # change observed since the last turn) as channel_context. The runner
            # prepends channel_context to the trigger text as context without it
            # being a trigger itself, so the fact reaches the agent on this turn.
            # Set via setattr so the adapter stays compatible with a MessageEvent
            # build that predates the channel_context field.
            ambient = self._take_pending_ambient_context(group_id_hex)
            if ambient and hasattr(hermes_event, "channel_context"):
                hermes_event.channel_context = ambient
            await self.handle_message(hermes_event)
        except asyncio.CancelledError:
            raise
        except Exception:
            # A failed turn in one group must not tear down the dispatcher or the queue; log
            # privacy-safely (no ids/payloads) and let other groups keep flowing.
            logger.warning("Marmot inbound dispatch failed", exc_info=True)

    async def _should_run_turn(self, event: Dict[str, Any]) -> bool:
        if self.group_activation == "always":
            return True
        if bool(event.get("mentions_self")):
            return True
        if matches_mention_pattern(str(event.get("text") or ""), self.mention_patterns):
            return True

        account_id_hex = event.get("account_id_hex") or self.account_id_hex
        group_id_hex = event["group_id_hex"]
        if not account_id_hex:
            account_id_hex = await self._ensure_account_id()

        cached = self._activation_cache.get(account_id_hex, group_id_hex)
        if cached is not None:
            return cached
        try:
            response = await self.client.group_info(account_id_hex, group_id_hex)
            is_direct = bool(response.get("is_direct"))
            self._activation_cache.set(account_id_hex, group_id_hex, is_direct)
            return is_direct
        except Exception:
            logger.debug("Marmot group membership lookup failed; skipping turn (fail-closed)")
            return False

    async def _download_inbound_media(self, event: Dict[str, Any]) -> Tuple[list[str], list[str]]:
        media_refs = event.get("media") or []
        if not isinstance(media_refs, list) or not media_refs:
            return [], []

        account_id_hex = event.get("account_id_hex") or self.account_id_hex
        group_id_hex = event["group_id_hex"]
        if not account_id_hex:
            try:
                account_id_hex = await self._ensure_account_id()
            except Exception:
                return [], []

        media_urls: list[str] = []
        media_types: list[str] = []
        for ref in media_refs:
            if not isinstance(ref, dict):
                continue
            try:
                response = await self.client.download_media(account_id_hex, group_id_hex, ref)
            except Exception:
                logger.debug("Marmot inbound media download failed; skipping attachment")
                continue
            path = str(response.get("path") or "").strip()
            if not path:
                continue
            source_path = Path(path).expanduser()
            if not source_path.is_file():
                continue
            file_name = str(response.get("file_name") or ref.get("file_name") or source_path.name or "attachment")
            try:
                staged_path = self._stage_inbound_media_file(source_path, file_name=file_name)
            except Exception:
                logger.debug("Marmot inbound media staging failed; skipping attachment")
                continue
            try:
                os.unlink(source_path)
            except OSError:
                pass
            media_urls.append(str(staged_path))
            media_types.append(str(response.get("media_type") or ref.get("media_type") or "application/octet-stream"))
        return media_urls, media_types

    def _stage_inbound_media_file(self, source_path: Path, *, file_name: str) -> Path:
        self._inbound_media_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(str(file_name or "attachment")).name or "attachment"
        dest = self._inbound_media_dir / f"{uuid.uuid4().hex}-{safe_name}"
        shutil.copy2(source_path, dest)
        dest.chmod(0o600)
        return dest

    def _debounce_key(self, event: Dict[str, Any]) -> str:
        # Mirror inbound-runtime.ts buildKey: account:group:sender.
        return (
            f"{event.get('account_id_hex') or ''}:"
            f"{event.get('group_id_hex') or ''}:"
            f"{event.get('sender_account_id_hex') or ''}"
        )

    def _enqueue_debounced(self, event: Dict[str, Any]) -> None:
        key = self._debounce_key(event)
        self._debounce_pending.setdefault(key, []).append(event)
        existing = self._debounce_tasks.get(key)
        if existing is not None and not existing.done():
            existing.cancel()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._debounce_tasks[key] = loop.create_task(self._debounce_flush_after(key))

    async def _debounce_flush_after(self, key: str) -> None:
        try:
            await asyncio.sleep(self.debounce_ms / 1000)
        except asyncio.CancelledError:
            return
        await self._flush_debounced(key)

    async def _flush_debounced(self, key: str) -> None:
        items = self._debounce_pending.pop(key, [])
        self._debounce_tasks.pop(key, None)
        if not items:
            return
        # Route the coalesced turn through the per-group queue too, so a debounced
        # batch stays FIFO-ordered with non-debounced messages in the same group
        # and a slow turn does not block the debounce-flush task (mirrors the
        # direct-dispatch path's per-group serialization).
        merged = _coalesce_inbound_events(items)
        group_id_hex = merged["group_id_hex"]
        self._inbound_queue.enqueue(
            group_id_hex,
            lambda evt=merged: self._dispatch_inbound_message(evt),
        )

    async def _handle_message_deleted(self, event: Dict[str, Any]) -> None:
        # A peer retracted a message. Surface it to the agent as quiet ambient
        # (next-turn) context, never a triggered reply. Privacy-safe log: no ids.
        logger.debug("Marmot inbound message deletion observed")
        group_id_hex = str(event.get("group_id_hex") or "")
        target_message_id_hex = str(event.get("target_message_id_hex") or "")
        context_key = f"marmot:message_deleted:{group_id_hex}:{target_message_id_hex}"
        await self._surface_ambient_context(event, "A message was deleted.", context_key)

    async def _handle_group_state_changed(self, event: Dict[str, Any]) -> None:
        # A durable group-state change (membership/admin/rename/avatar). Surfaced
        # to the agent as quiet ambient context; the mapped sentence never carries
        # a member pubkey. Privacy-safe log: no change contents.
        logger.debug("Marmot inbound group state change observed")
        change = str(event.get("change") or "")
        group_id_hex = str(event.get("group_id_hex") or "")
        account_id_hex = str(event.get("account_id_hex") or self.account_id_hex or "")
        if account_id_hex and group_id_hex:
            self._activation_cache.invalidate(account_id_hex, group_id_hex)
        sentence = group_state_change_sentence(change, event.get("detail"))
        context_key = f"marmot:group_state_changed:{group_id_hex}:{change}"
        await self._surface_ambient_context(event, sentence, context_key)

    async def _surface_ambient_context(
        self,
        event: Dict[str, Any],
        text: str,
        context_key: str,
    ) -> None:
        # Dedupe repeated surfacings of the same fact.
        if context_key in self._recent_ambient_keys:
            return
        self._recent_ambient_keys.add(context_key)

        group_id_hex = str(event.get("group_id_hex") or "")
        # Quiet next-turn context: an ambient event is NEVER a reply trigger, so
        # do NOT route it through handle_message() (which would start/queue an
        # agent turn). Hermes' BasePlatformAdapter has no system-event surface
        # (unlike OpenClaw's api.runtime.system.enqueueSystemEvent), so we mirror
        # OpenClaw's quiet-context behavior by buffering the sentence per group
        # and prepending it to the NEXT real inbound message's channel_context.
        # If no message ever follows, the fact is only logged — matching
        # OpenClaw's "when omitted, those events are only logged" degraded mode.
        self._pending_ambient_context.setdefault(group_id_hex, []).append(text)

    def _take_pending_ambient_context(self, group_id_hex: str) -> Optional[str]:
        # Drain and join the buffered ambient sentences for a group. Returns None
        # when nothing is pending so callers can leave channel_context unset.
        pending = self._pending_ambient_context.pop(group_id_hex, None)
        if not pending:
            return None
        return "\n".join(pending)

    async def _maybe_send_profile_prompt_on_join(self, account_id_hex: str, group_id_hex: str) -> None:
        store = self.profile_name_onboarding
        if store is None:
            return

        suggested = valid_profile_name(self.agent_name)
        if not await store.try_claim_prompt(account_id_hex, group_id_hex, suggested):
            return

        result = await self._send_final_direct(
            group_id_hex,
            build_profile_prompt(suggested),
        )
        if not result.success:
            logger.debug("Marmot profile-name prompt send failed on join: %s", result.error)
            await store.clear(account_id_hex)

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

            # Claim the one-time prompt slot atomically BEFORE sending. Under the new
            # per-group concurrency (#513), two first messages for the same account in
            # different groups could otherwise both read empty state and both prompt
            # (double-prompting and swallowing both user messages). try_claim_prompt() is
            # the single-lock claim that lets exactly one caller win; everyone else returns
            # False here and falls through to a normal turn.
            if not await store.try_claim_prompt(
                account_id_hex,
                group_id_hex,
                valid_profile_name(self.agent_name),
            ):
                return False

            result = await self._send_final_direct(
                group_id_hex,
                build_profile_prompt(valid_profile_name(self.agent_name)),
                reply_to_message_id_hex=message_id_hex,
            )
            if not result.success:
                # We claimed the slot but could not deliver the prompt; release it so a
                # later inbound message retries, instead of permanently swallowing this one.
                logger.debug("Marmot profile-name prompt send failed: %s", result.error)
                await store.clear(account_id_hex)
                return False
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
        if action == "affirm":
            state = await store.get(account_id_hex)
            suggested = valid_profile_name(state.get("suggested_name"))
            if not suggested:
                await self._send_final_direct(
                    group_id_hex,
                    PROFILE_NAME_EMPTY,
                    reply_to_message_id_hex=message_id_hex,
                )
                return True
            name = suggested
        elif action == "invalid":
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
    if media_files:
        results = []
        caption = str(message or "")
        for index, media_path in enumerate(media_files):
            path = Path(str(media_path)).expanduser()
            media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            result = await adapter._send_media_upload(
                str(chat_id),
                path=str(path),
                media_type=media_type,
                file_name=path.name,
                caption=caption if index == 0 else None,
            )
            if not result.success:
                return {"error": result.error or "Marmot media send failed"}
            results.append(result.message_id)
        return {"success": True, "message_id": results[-1] if results else None}
    result = await adapter.send(str(chat_id), str(message or ""))
    if result.success:
        return {"success": True, "message_id": result.message_id}
    return {"error": result.error or "Marmot send failed"}


def _delete_marmot_message_tool(args: Dict[str, Any]) -> str:
    message_id = str(args.get("message_id") or "").strip()
    if not message_id:
        return json.dumps({"ok": False, "error": "message_id required"})

    chat_id: Optional[str] = None
    target = str(args.get("target") or "").strip()
    if target:
        parts = target.split(":", 1)
        if len(parts) == 2 and parts[0].strip().lower() == "marmot":
            chat_id = parts[1].strip() or None
        else:
            chat_id = target

    try:
        from gateway.config import Platform
        from gateway.run import _gateway_runner_ref
        from model_tools import _run_async

        runner = _gateway_runner_ref()
        adapter = runner.adapters.get(Platform("marmot")) if runner is not None else None
        if adapter is None:
            return json.dumps(
                {
                    "ok": False,
                    "error": "delete_marmot_message requires a live Marmot adapter in the running gateway",
                }
            )
        deleted = _run_async(adapter.delete_message(chat_id or "", message_id))
        return json.dumps({"ok": bool(deleted), "deleted": bool(deleted)})
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})


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
    register_tool = getattr(ctx, "register_tool", None)
    if callable(register_tool):
        register_tool(
            name="delete_marmot_message",
            toolset="platform",
            schema={
                "type": "object",
                "properties": {
                    "message_id": {
                        "type": "string",
                        "description": "Hex id of the durable Marmot message to retract (kind-5 delete).",
                    },
                    "target": {
                        "type": "string",
                        "description": (
                            "Optional Marmot target as marmot:<group_id_hex>. "
                            "Omit when the send-time cache can resolve the group."
                        ),
                    },
                },
                "required": ["message_id"],
            },
            handler=_delete_marmot_message_tool,
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


def resolve_group_activation(extra: Dict[str, Any]) -> Literal["mention", "always"]:
    configured = _first_config_value(
        extra,
        "group_activation",
        "groupActivation",
        env="MARMOT_GROUP_ACTIVATION",
    )
    if configured is None:
        return DEFAULT_GROUP_ACTIVATION
    value = str(configured).strip().lower()
    if value == "always":
        return "always"
    return "mention"


def resolve_mention_patterns(extra: Dict[str, Any]) -> list[str]:
    configured = extra.get("mention_patterns")
    if configured is None:
        configured = extra.get("mentionPatterns")
    if configured is None:
        configured = os.getenv("MARMOT_MENTION_PATTERNS")
    patterns = _split_config_list(configured)
    agent_name = _first_config_value(extra, "agent_name", "agentName", env="MARMOT_AGENT_NAME")
    if agent_name:
        name = str(agent_name).strip()
        if name and name not in patterns:
            patterns.append(name)
    return patterns


def resolve_debounce_ms(extra: Dict[str, Any]) -> int:
    """Resolve the optional inbound debounce window in milliseconds.

    Reads ``MARMOT_DEBOUNCE_MS`` env or the ``debounce_ms`` extra config. A
    non-negative integer; 0 or absent means disabled (current behavior). A
    negative or non-integer value is clamped to 0 (disabled).
    """
    configured = os.getenv("MARMOT_DEBOUNCE_MS")
    if configured is None or str(configured).strip() == "":
        configured = extra.get("debounce_ms")
    if configured is None or str(configured).strip() == "":
        return 0
    try:
        value = int(str(configured).strip())
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


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
    if value.casefold() in PROFILE_NAME_AFFIRM_REPLIES:
        return ("affirm", None, "")
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


def effective_plaintext_cap(policy_max_plaintext_frame_len: Any) -> int:
    try:
        policy_cap = int(policy_max_plaintext_frame_len)
    except (TypeError, ValueError):
        return AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN
    if policy_cap <= 0:
        return AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN
    return min(policy_cap, AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN)


def effective_stream_chunk_bytes(requested_chunk_bytes: int, policy_max_plaintext_frame_len: Any) -> int:
    requested = int(requested_chunk_bytes)
    if requested <= 0 or requested > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN:
        return requested
    return min(requested, effective_plaintext_cap(policy_max_plaintext_frame_len))


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


def _encode_quic_varint(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise ValueError("QUIC varint value must be non-negative")
    if value < 0x40:
        return value.to_bytes(1, "big")
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    if value < 0x4000000000000000:
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("QUIC varint value exceeds 2^62-1")


def _hash_len_prefixed(hasher: Any, data: bytes) -> None:
    hasher.update(_encode_quic_varint(len(data)))
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
