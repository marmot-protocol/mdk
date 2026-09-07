"""Private durable quiet-context facts for the Hermes Marmot adapter.

Only hashed routing/dedupe keys and a small allowlisted fact kind cross the
process boundary. Message text, display names, pubkeys, tokens, and full Marmot
identifiers are never persisted here.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = 1
_ALLOWED_KINDS = frozenset(
    {
        "message_deleted",
        "message_edited",
        "reaction_added",
        "reaction_removed",
        "group_state:member_added",
        "group_state:member_removed",
        "group_state:member_left",
        "group_state:admin_added",
        "group_state:admin_removed",
        "group_state:group_renamed",
        "group_state:group_avatar_changed",
        "group_state:disappearing_timer_changed",
        "group_state:changed",
    }
)


class AmbientContextError(RuntimeError):
    """The private ambient-fact store could not be used safely."""


@dataclass(frozen=True)
class AmbientFact:
    seq: int
    kind: str


def _digest(domain: bytes, value: str) -> bytes:
    return hashlib.sha256(domain + value.encode("utf-8")).digest()


class AmbientContextStore:
    """Crash-safe bounded SQLite store for quiet next-turn facts."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_groups: int = 256,
        max_events_per_group: int = 16,
        max_events: int = 2048,
        max_state_bytes: int = 1024 * 1024,
        max_age_s: int = 7 * 24 * 60 * 60,
    ) -> None:
        self.path = Path(path).expanduser().absolute()
        self.max_groups = max(1, int(max_groups))
        self.max_events_per_group = max(1, int(max_events_per_group))
        self.max_events = max(1, int(max_events))
        self.max_state_bytes = max(4096, int(max_state_bytes))
        self.max_age_s = max(0, int(max_age_s))
        self._db: sqlite3.Connection | None = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @property
    def is_open(self) -> bool:
        return self._db is not None

    def open(self) -> None:
        if self._db is not None:
            return
        self._prepare_private_parent()
        self._refuse_unsafe_existing_file(self.path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
            db = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA wal_autocheckpoint=1")
            db.execute("PRAGMA journal_size_limit=32768")
            db.execute("PRAGMA busy_timeout=5000")
            self._db = db
            self._initialize_schema()
            page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
            db.execute(f"PRAGMA max_page_count={max(4, self.max_state_bytes // page_size)}")
            result = db.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise AmbientContextError("ambient context integrity check failed")
            with db:
                self._gc(time.time())
            self._checkpoint()
        except Exception as exc:
            self.close()
            if isinstance(exc, AmbientContextError):
                raise
            raise AmbientContextError("ambient context store could not be opened") from exc

    def close(self) -> None:
        db, self._db = self._db, None
        if db is None:
            return
        try:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            db.close()

    def record(self, group_id: str, event_key: str, kind: str, *, observed_at: float | None = None) -> bool:
        if kind not in _ALLOWED_KINDS:
            raise ValueError("unsupported ambient fact kind")
        self.open()
        db = self._require_db()
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        dedupe_key = _digest(b"marmot-ambient-event-v1\0", event_key)
        now = time.time() if observed_at is None else float(observed_at)
        try:
            with db:
                self._gc(now)
                exists = db.execute("SELECT 1 FROM facts WHERE event_key=?", (dedupe_key,)).fetchone()
                if exists is not None:
                    return False
                group_exists = db.execute("SELECT 1 FROM facts WHERE group_key=? LIMIT 1", (group_key,)).fetchone()
                if group_exists is None:
                    groups = int(db.execute("SELECT count(DISTINCT group_key) FROM facts").fetchone()[0])
                    if groups >= self.max_groups:
                        oldest = db.execute(
                            "SELECT group_key FROM facts GROUP BY group_key ORDER BY min(seq),hex(group_key) LIMIT 1"
                        ).fetchone()
                        if oldest is not None:
                            db.execute("DELETE FROM facts WHERE group_key=?", (oldest[0],))
                db.execute(
                    "INSERT INTO facts(group_key,event_key,kind,observed_at) VALUES(?,?,?,?)",
                    (group_key, dedupe_key, kind, now),
                )
                self._evict_over_bounds(group_key)
            self._checkpoint()
            return True
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient fact commit failed") from exc

    def pending(self, group_id: str, *, now: float | None = None) -> list[AmbientFact]:
        self.open()
        db = self._require_db()
        at = time.time() if now is None else float(now)
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                self._gc(at)
                rows = db.execute(
                    "SELECT seq,kind FROM facts WHERE group_key=? ORDER BY seq", (group_key,)
                ).fetchall()
            self._checkpoint()
            return [AmbientFact(int(row["seq"]), str(row["kind"])) for row in rows]
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient facts could not be read") from exc

    def acknowledge(self, group_id: str, seqs: Iterable[int]) -> int:
        ids = tuple(dict.fromkeys(int(value) for value in seqs))
        if not ids:
            return 0
        self.open()
        db = self._require_db()
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                changed = db.execute(
                    f"DELETE FROM facts WHERE group_key=? AND seq IN ({','.join('?' for _ in ids)})",
                    (group_key, *ids),
                ).rowcount
            self._checkpoint()
            return int(changed)
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient acknowledgement failed") from exc

    def stats(self) -> dict[str, int]:
        """Return privacy-safe bounded-state counters for diagnostics and tests."""
        self.open()
        db = self._require_db()
        row = db.execute(
            "SELECT count(DISTINCT group_key),count(*),"
            "COALESCE(sum(length(group_key)+length(event_key)+length(kind)+24),0) FROM facts"
        ).fetchone()
        return {"groups": int(row[0]), "events": int(row[1]), "state_bytes": int(row[2])}

    def _initialize_schema(self) -> None:
        db = self._require_db()
        with db:
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, SCHEMA_VERSION}:
                raise AmbientContextError("unsupported ambient context schema")
            db.execute(
                "CREATE TABLE IF NOT EXISTS facts("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "group_key BLOB NOT NULL,event_key BLOB NOT NULL UNIQUE,"
                "kind TEXT NOT NULL,observed_at REAL NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS facts_group_seq ON facts(group_key,seq)")
            db.execute("CREATE INDEX IF NOT EXISTS facts_age_seq ON facts(observed_at,seq)")
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _gc(self, now: float) -> None:
        if self.max_age_s <= 0:
            self._require_db().execute("DELETE FROM facts")
        else:
            self._require_db().execute(
                "DELETE FROM facts WHERE observed_at<?", (now - self.max_age_s,)
            )

    def _evict_over_bounds(self, group_key: bytes) -> None:
        db = self._require_db()
        group_count = int(db.execute("SELECT count(*) FROM facts WHERE group_key=?", (group_key,)).fetchone()[0])
        if group_count > self.max_events_per_group:
            db.execute(
                "DELETE FROM facts WHERE seq IN (SELECT seq FROM facts WHERE group_key=? ORDER BY seq LIMIT ?)",
                (group_key, group_count - self.max_events_per_group),
            )
        total = int(db.execute("SELECT count(*) FROM facts").fetchone()[0])
        if total > self.max_events:
            db.execute(
                "DELETE FROM facts WHERE seq IN (SELECT seq FROM facts ORDER BY seq LIMIT ?)",
                (total - self.max_events,),
            )
        while self._logical_bytes() > self.max_state_bytes:
            changed = db.execute("DELETE FROM facts WHERE seq=(SELECT min(seq) FROM facts)").rowcount
            if not changed:
                raise AmbientContextError("ambient schema exceeds configured byte bound")

    def _logical_bytes(self) -> int:
        row = self._require_db().execute(
            "SELECT COALESCE(sum(length(group_key)+length(event_key)+length(kind)+24),0) FROM facts"
        ).fetchone()
        return int(row[0])

    def _checkpoint(self) -> None:
        db = self._require_db()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                os.chmod(candidate, 0o600, follow_symlinks=False)
            except FileNotFoundError:
                pass

    def _prepare_private_parent(self) -> None:
        parent = self.path.parent
        current = Path(self.path.anchor)
        for component in parent.parts[1:]:
            current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise AmbientContextError("ambient context parent path is unsafe")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise AmbientContextError("ambient context parent is unsafe")
        mode = stat.S_IMODE(parent.stat().st_mode)
        if mode & 0o077:
            try:
                parent.chmod(0o700)
            except OSError as exc:
                raise AmbientContextError("ambient context parent is not private") from exc
        if stat.S_IMODE(parent.stat().st_mode) & 0o077:
            raise AmbientContextError("ambient context parent is not private")

    @staticmethod
    def _refuse_unsafe_existing_file(path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise AmbientContextError("ambient context file is unsafe")

    def _require_db(self) -> sqlite3.Connection:
        if self._db is None:
            raise AmbientContextError("ambient context store is not open")
        return self._db
