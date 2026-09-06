"""Crash-safe inbound obligation spool for the Hermes Marmot adapter.

The spool closes the loss window before Hermes' in-memory debounce and queue.
It does not claim exactly-once tool effects or a durable Hermes handoff: a
record that crossed the current host boundary but whose outcome was not
observed becomes ``unresolved`` after restart and is never replayed blindly.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 1
TERMINAL_STATES = frozenset({"completed", "intentionally_skipped", "unresolved", "failed"})


class InboundSpoolError(RuntimeError):
    """The durable intake boundary is unavailable; callers must fail closed."""


class SpoolFullError(InboundSpoolError):
    """Non-terminal obligations exhausted the configured spool bound."""


class SpoolLockedError(InboundSpoolError):
    """Another live process owns this spool."""


# Compatibility name kept local to the first schema implementation.
InboundSpoolFull = SpoolFullError


class StaleClaim(InboundSpoolError):
    """A claim transition was attempted by the wrong execution generation."""


@dataclass(frozen=True)
class SpoolRecord:
    seq: int
    message_id: str
    group_id: str
    state: str
    event: dict[str, Any]
    source_ids: tuple[str, ...]
    reply_anchor: Optional[str]
    attempts: int
    next_attempt_at: float
    disposition: Optional[str]


class InboundSpool:
    """Single-process, schema-versioned SQLite obligation journal."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_pending: int = 4096,
        max_bytes: int = 64 * 1024 * 1024,
        max_terminal: int = 8192,
        terminal_retention_s: int = 7 * 24 * 60 * 60,
    ) -> None:
        self.path = Path(path).expanduser()
        self.max_pending = max(1, int(max_pending))
        self.max_bytes = int(max_bytes)
        if self.max_bytes < 1024 * 1024:
            raise ValueError("inbound spool max_bytes must be at least 1 MiB")
        self.max_terminal = max(0, int(max_terminal))
        self.terminal_retention_s = max(0, int(terminal_retention_s))
        self.owner_id = uuid.uuid4().hex
        self.generation = 0
        self._lock_fd: Optional[int] = None
        self._db: Optional[sqlite3.Connection] = None

    @property
    def is_open(self) -> bool:
        return self._db is not None

    def __del__(self) -> None:
        try:
            self.close(graceful=True)
        except Exception:
            pass

    def open(self) -> dict[str, int]:
        if self._db is not None:
            return {"reclaimed": 0, "unresolved": 0}
        self._prepare_private_parent()
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            try:
                os.close(lock_fd)  # type: ignore[possibly-undefined]
            except Exception:
                pass
            raise SpoolLockedError("inbound spool execution owner is unavailable") from exc

        try:
            self._refuse_unsafe_existing_file(self.path)
            create_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, create_flags, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
            # Explicit transaction mode is required: record/batch/transition
            # methods use ``with db`` as their crash-atomic commit boundary.
            db = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA wal_autocheckpoint=1")
            db.execute("PRAGMA journal_size_limit=32768")
            db.execute("PRAGMA busy_timeout=5000")
            self._db = db
            self._lock_fd = lock_fd
            self._initialize_schema()
            page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
            db_page_budget = max(1, (self.max_bytes - 65536) // page_size)
            db.execute(f"PRAGMA max_page_count={db_page_budget}")
            result = db.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise InboundSpoolError("inbound spool integrity check failed")
            recovery = self._start_generation_and_recover()
            self._checkpoint_and_verify_bound()
            return recovery
        except Exception as exc:
            self._close_handles(lock_fd)
            if isinstance(exc, InboundSpoolError):
                raise
            raise InboundSpoolError("inbound spool could not be opened") from exc

    def close(self, *, graceful: bool = True) -> None:
        db = self._db
        lock_fd = self._lock_fd
        if db is None:
            return
        try:
            if graceful:
                with db:
                    db.execute(
                        "UPDATE events SET state='pending', owner_id=NULL, generation=NULL, "
                        "disposition='graceful_release', changed_at=? "
                        "WHERE state='claimed' AND owner_id=? AND generation=?",
                        (time.time(), self.owner_id, self.generation),
                    )
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            self._close_handles(lock_fd)

    def record(
        self,
        event: dict[str, Any],
        *,
        debounce_buffered: bool = False,
    ) -> tuple[bool, str]:
        db = self._require_db()
        account_id = str(event["account_id_hex"])
        group_id = str(event["group_id_hex"])
        message_id = str(event["message_id_hex"])
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        now = time.time()
        try:
            with db:
                row = db.execute(
                    "SELECT state FROM events WHERE account_id=? AND group_id=? AND message_id=?",
                    (account_id, group_id, message_id),
                ).fetchone()
                if row is not None:
                    return False, str(row[0])
                self._gc_terminal_locked(now)
                pending = int(db.execute(
                    "SELECT count(*) FROM events WHERE state IN ('pending','claimed','coalesced')"
                ).fetchone()[0])
                if pending >= self.max_pending or self._allocated_bytes() + len(payload.encode("utf-8")) > self.max_bytes:
                    raise InboundSpoolFull("inbound spool capacity exhausted")
                db.execute(
                    "INSERT INTO events(account_id,group_id,message_id,state,event_json,source_ids_json,"
                    "reply_anchor,attempts,next_attempt_at,disposition,created_at,changed_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        account_id,
                        group_id,
                        message_id,
                        "pending",
                        payload,
                        json.dumps([message_id]),
                        self._reply_anchor(event),
                        0,
                        0.0,
                        "debounce_buffered" if debounce_buffered else None,
                        now,
                        now,
                    ),
                )
            self._checkpoint_and_verify_bound()
            return True, "pending"
        except InboundSpoolError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise InboundSpoolError("inbound spool journal commit failed") from exc

    def form_batch(self, source_ids: Iterable[str], merged_event: dict[str, Any]) -> str:
        ids = tuple(dict.fromkeys(str(value) for value in source_ids if value))
        if not ids:
            raise InboundSpoolError("cannot form an empty inbound batch")
        merged_message_id = str(merged_event["message_id_hex"])
        if merged_message_id not in ids:
            raise InboundSpoolError("batch representative is not a source event")
        # The oldest source id owns the row so its sequence keeps the coalesced
        # turn ahead of later same-group events. The merged event still retains
        # the newest message id as the user-visible reply representative.
        representative = ids[0]
        db = self._require_db()
        now = time.time()
        with db:
            rows = db.execute(
                f"SELECT message_id,state FROM events WHERE message_id IN ({','.join('?' for _ in ids)})",
                ids,
            ).fetchall()
            if len(rows) != len(ids) or any(row["state"] != "pending" for row in rows):
                raise InboundSpoolError("inbound batch members are not all pending")
            db.execute(
                "UPDATE events SET event_json=?, source_ids_json=?, reply_anchor=?, batch_id=?, "
                "next_attempt_at=0, disposition='batch_representative', changed_at=? WHERE message_id=?",
                (
                    json.dumps(merged_event, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(list(ids)),
                    self._reply_anchor(merged_event),
                    representative,
                    now,
                    representative,
                ),
            )
            for message_id in ids:
                if message_id == representative:
                    continue
                db.execute(
                    "UPDATE events SET state='coalesced', batch_id=?, disposition='coalesced_pending', "
                    "changed_at=? WHERE message_id=?",
                    (representative, now, message_id),
                )
        self._checkpoint_and_verify_bound()
        return representative

    def release_debounce(self, source_ids: Iterable[str], *, reason: str) -> int:
        """Make abandoned debounce rows eligible for ordinary FIFO admission.

        The state/disposition predicate is a compare-and-set boundary: a row
        that already advanced to a batch, claim, or terminal state is untouched.
        """
        ids = tuple(dict.fromkeys(str(value) for value in source_ids if value))
        if not ids:
            return 0
        db = self._require_db()
        now = time.time()
        try:
            with db:
                changed = db.execute(
                    f"UPDATE events SET next_attempt_at=0,disposition=?,changed_at=? "
                    f"WHERE message_id IN ({','.join('?' for _ in ids)}) "
                    "AND state='pending' AND disposition='debounce_buffered'",
                    (reason, now, *ids),
                ).rowcount
            self._checkpoint_and_verify_bound()
            return int(changed)
        except InboundSpoolError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise InboundSpoolError("inbound debounce release failed") from exc

    def due(self, *, now: Optional[float] = None) -> list[SpoolRecord]:
        db = self._require_db()
        at = time.time() if now is None else float(now)
        rows = db.execute(
            "SELECT * FROM events e WHERE e.state='pending' AND e.next_attempt_at<=? "
            "AND COALESCE(e.disposition,'')<>'debounce_buffered' "
            "AND (e.batch_id IS NULL OR e.batch_id=e.message_id) "
            "AND NOT EXISTS (SELECT 1 FROM events older WHERE older.group_id=e.group_id "
            "AND older.seq<e.seq AND older.state NOT IN ('handed','completed','intentionally_skipped','unresolved','failed','coalesced')) "
            "ORDER BY e.seq",
            (at,),
        ).fetchall()
        return [self._record_from_row(row) for row in rows]

    def claim(self, message_id: str, *, ignore_backoff: bool = False) -> SpoolRecord:
        db = self._require_db()
        now = time.time()
        with db:
            row = db.execute("SELECT * FROM events WHERE message_id=?", (message_id,)).fetchone()
            if (
                row is None
                or row["state"] != "pending"
                or row["disposition"] == "debounce_buffered"
                or (not ignore_backoff and float(row["next_attempt_at"]) > now)
            ):
                raise StaleClaim("inbound obligation is no longer pending")
            blocked = db.execute(
                "SELECT 1 FROM events WHERE group_id=? AND seq<? AND state NOT IN "
                "('handed','completed','intentionally_skipped','unresolved','failed','coalesced') LIMIT 1",
                (row["group_id"], row["seq"]),
            ).fetchone()
            active = db.execute(
                "SELECT 1 FROM events WHERE group_id=? AND state='claimed' LIMIT 1",
                (row["group_id"],),
            ).fetchone()
            if blocked is not None or active is not None:
                raise StaleClaim("an older or active same-group obligation exists")
            changed = db.execute(
                "UPDATE events SET state='claimed',owner_id=?,generation=?,disposition='claimed',changed_at=? "
                "WHERE message_id=? AND state='pending'",
                (self.owner_id, self.generation, now, message_id),
            ).rowcount
            if changed != 1:
                raise StaleClaim("inbound claim lost a compare-and-set race")
            row = db.execute("SELECT * FROM events WHERE message_id=?", (message_id,)).fetchone()
        self._checkpoint_and_verify_bound()
        return self._record_from_row(row)

    def defer(self, message_id: str, *, delay_s: float, reason: str) -> None:
        db = self._require_db()
        now = time.time()
        with db:
            changed = db.execute(
                "UPDATE events SET state='pending',owner_id=NULL,generation=NULL,attempts=attempts+1,"
                "next_attempt_at=?,disposition=?,changed_at=? WHERE message_id=? AND state='claimed' "
                "AND owner_id=? AND generation=?",
                (now + max(0.01, float(delay_s)), reason, now, message_id, self.owner_id, self.generation),
            ).rowcount
            if changed != 1:
                raise StaleClaim("cannot defer a stale inbound claim")
        self._checkpoint_and_verify_bound()

    def transition(self, message_id: str, state: str, disposition: str) -> None:
        if state not in {"handed", "completed", "intentionally_skipped", "unresolved", "failed"}:
            raise ValueError("unsupported inbound spool state")
        db = self._require_db()
        now = time.time()
        with db:
            row = db.execute("SELECT state FROM events WHERE message_id=?", (message_id,)).fetchone()
            expected = "claimed" if state in {"handed", "intentionally_skipped", "failed"} else "handed"
            if row is None or row[0] != expected:
                raise StaleClaim("inbound transition does not own the expected state")
            changed = db.execute(
                "UPDATE events SET state=?,disposition=?,changed_at=? WHERE message_id=? AND state=? "
                "AND owner_id=? AND generation=?",
                (state, disposition, now, message_id, expected, self.owner_id, self.generation),
            ).rowcount
            if changed != 1:
                raise StaleClaim("inbound transition lost its generation-bound claim")
            if state in TERMINAL_STATES:
                member_disposition = f"coalesced_{disposition}"
                db.execute(
                    "UPDATE events SET state=?,disposition=?,owner_id=NULL,generation=NULL,changed_at=? "
                    "WHERE batch_id=? AND message_id<>? AND state='coalesced'",
                    (state, member_disposition, now, message_id, message_id),
                )
        self._checkpoint_and_verify_bound()

    def snapshot(self) -> dict[str, int]:
        db = self._require_db()
        return {str(row[0]): int(row[1]) for row in db.execute("SELECT state,count(*) FROM events GROUP BY state")}

    def get(self, message_id: str) -> Optional[SpoolRecord]:
        row = self._require_db().execute("SELECT * FROM events WHERE message_id=?", (message_id,)).fetchone()
        return self._record_from_row(row) if row is not None else None

    def _start_generation_and_recover(self) -> dict[str, int]:
        db = self._require_db()
        now = time.time()
        with db:
            generation = int(db.execute("SELECT value FROM spool_meta WHERE key='generation'").fetchone()[0]) + 1
            db.execute("UPDATE spool_meta SET value=? WHERE key='generation'", (str(generation),))
            self.generation = generation
            handed = int(db.execute("SELECT count(*) FROM events WHERE state='handed'").fetchone()[0])
            db.execute(
                "UPDATE events SET state='unresolved',owner_id=NULL,generation=NULL,"
                "disposition='host_handoff_outcome_unknown',changed_at=? WHERE state='handed'",
                (now,),
            )
            db.execute(
                "UPDATE events SET state='unresolved',disposition='coalesced_host_handoff_outcome_unknown',"
                "owner_id=NULL,generation=NULL,changed_at=? "
                "WHERE state='coalesced' AND batch_id IN (SELECT message_id FROM events WHERE state='unresolved')",
                (now,),
            )
            claimed = int(db.execute("SELECT count(*) FROM events WHERE state='claimed'").fetchone()[0])
            db.execute(
                "UPDATE events SET state='pending',owner_id=NULL,generation=NULL,next_attempt_at=0,"
                "disposition='recovered_abandoned_claim',changed_at=? WHERE state='claimed'",
                (now,),
            )
            db.execute(
                "UPDATE events SET next_attempt_at=0,disposition='recovered_debounce_buffer',changed_at=? "
                "WHERE state='pending' AND disposition='debounce_buffered'",
                (now,),
            )
            db.execute("DELETE FROM owners")
            db.execute(
                "INSERT OR REPLACE INTO owners(owner_id,generation,pid,started_at) VALUES(?,?,?,?)",
                (self.owner_id, generation, os.getpid(), now),
            )
        return {"reclaimed": claimed, "unresolved": handed}

    def _initialize_schema(self) -> None:
        db = self._require_db()
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, SCHEMA_VERSION):
            raise InboundSpoolError("unsupported inbound spool schema version")
        if version == 0:
            with db:
                db.executescript(
                    """
                    CREATE TABLE spool_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO spool_meta(key,value) VALUES('generation','0');
                    CREATE TABLE owners(
                        owner_id TEXT PRIMARY KEY,
                        generation INTEGER NOT NULL,
                        pid INTEGER NOT NULL,
                        started_at REAL NOT NULL
                    );
                    CREATE TABLE events(
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id TEXT NOT NULL,
                        group_id TEXT NOT NULL,
                        message_id TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL CHECK(state IN ('pending','claimed','handed','completed','intentionally_skipped','unresolved','failed','coalesced')),
                        event_json TEXT NOT NULL,
                        source_ids_json TEXT NOT NULL,
                        reply_anchor TEXT,
                        batch_id TEXT,
                        owner_id TEXT,
                        generation INTEGER,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        next_attempt_at REAL NOT NULL DEFAULT 0,
                        disposition TEXT,
                        created_at REAL NOT NULL,
                        changed_at REAL NOT NULL,
                        UNIQUE(account_id,group_id,message_id)
                    );
                    CREATE INDEX events_due ON events(state,next_attempt_at,seq);
                    CREATE INDEX events_group_fifo ON events(group_id,seq);
                    PRAGMA user_version=1;
                    """
                )
        columns = {str(row[1]) for row in db.execute("PRAGMA table_info(events)")}
        if {"seq", "account_id", "group_id", "message_id", "state", "event_json"} - columns:
            raise InboundSpoolError("inbound spool schema is corrupt")

    def _gc_terminal_locked(self, now: float) -> None:
        db = self._require_db()
        cutoff = now - self.terminal_retention_s
        db.execute(
            "DELETE FROM events WHERE state IN ('handed','completed','intentionally_skipped','unresolved','failed') "
            "AND changed_at<?",
            (cutoff,),
        )
        terminal = db.execute(
            "SELECT message_id FROM events WHERE state IN ('handed','completed','intentionally_skipped','unresolved','failed') "
            "ORDER BY changed_at DESC LIMIT -1 OFFSET ?",
            (self.max_terminal,),
        ).fetchall()
        for row in terminal:
            db.execute("DELETE FROM events WHERE message_id=?", (row[0],))

    def _allocated_bytes(self) -> int:
        total = 0
        for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                total += candidate.stat().st_size
            except FileNotFoundError:
                pass
        return total

    def _checkpoint_and_verify_bound(self) -> None:
        db = self._require_db()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self._make_sidecars_private()
        if self._allocated_bytes() > self.max_bytes:
            raise InboundSpoolFull("inbound spool storage bound exhausted")

    def _prepare_private_parent(self) -> None:
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise InboundSpoolError("inbound spool parent is unsafe")
        mode = stat.S_IMODE(parent.stat().st_mode)
        if mode & 0o077:
            raise InboundSpoolError("inbound spool parent permissions are too broad")

    @staticmethod
    def _refuse_unsafe_existing_file(path: Path) -> None:
        if not path.exists():
            return
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise InboundSpoolError("inbound spool file is unsafe")

    def _make_sidecars_private(self) -> None:
        for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                os.chmod(candidate, 0o600, follow_symlinks=False)
            except FileNotFoundError:
                pass

    def _close_handles(self, lock_fd: Optional[int]) -> None:
        db, self._db = self._db, None
        self._lock_fd = None
        if db is not None:
            db.close()
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _require_db(self) -> sqlite3.Connection:
        if self._db is None:
            raise InboundSpoolError("inbound spool is not open")
        return self._db

    @staticmethod
    def _reply_anchor(event: dict[str, Any]) -> Optional[str]:
        reply = event.get("reply_to")
        if isinstance(reply, dict) and reply.get("message_id_hex"):
            return str(reply["message_id_hex"])
        value = event.get("reply_to_message_id_hex")
        return str(value) if value else None

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> SpoolRecord:
        return SpoolRecord(
            seq=int(row["seq"]),
            message_id=str(row["message_id"]),
            group_id=str(row["group_id"]),
            state=str(row["state"]),
            event=json.loads(row["event_json"]),
            source_ids=tuple(json.loads(row["source_ids_json"])),
            reply_anchor=str(row["reply_anchor"]) if row["reply_anchor"] else None,
            attempts=int(row["attempts"]),
            next_attempt_at=float(row["next_attempt_at"]),
            disposition=str(row["disposition"]) if row["disposition"] else None,
        )
