"""Private durable quiet-context facts for the Hermes Marmot adapter.

Only hashed routing/dedupe keys and a small allowlisted fact kind cross the
process boundary. Message text, display names, pubkeys, tokens, and full Marmot
identifiers are never persisted here.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import sqlite3
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 3
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


@dataclass(frozen=True)
class AmbientClaim:
    token: str
    facts: tuple[AmbientFact, ...]


def _digest(domain: bytes, value: str) -> bytes:
    return hashlib.sha256(domain + value.encode("utf-8")).digest()


class AmbientContextStore:
    """Crash-safe bounded SQLite store for quiet next-turn facts.

    One process owns the store through a private advisory lock. Within that
    owner, per-group claims prevent overlapping dispatches from attaching the
    same snapshot. A clean close releases claims; a replacement process can
    reclaim an abruptly abandoned claim only after acquiring the exclusive
    lock. Acknowledged event hashes remain as bounded tombstones so connector
    replay cannot requeue an already accepted fact.
    """

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
        self.lock_path = Path(str(self.path) + ".lock")
        self.max_groups = max(1, int(max_groups))
        self.max_events_per_group = max(1, int(max_events_per_group))
        self.max_events = max(1, int(max_events))
        self.max_state_bytes = max(4096, int(max_state_bytes))
        self.max_age_s = max(0, int(max_age_s))
        self.owner_id = uuid.uuid4().hex
        self._db: sqlite3.Connection | None = None
        self._lock_fd: int | None = None

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
        self._refuse_unsafe_existing_file(self.lock_path)
        lock_fd: int | None = None
        try:
            lock_fd = self._open_private_file(self.lock_path)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AmbientContextError("ambient context store is already owned") from exc
            fd = self._open_private_file(self.path)
            os.close(fd)
            db = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA wal_autocheckpoint=1")
            db.execute("PRAGMA journal_size_limit=32768")
            db.execute("PRAGMA busy_timeout=5000")
            self._db = db
            self._lock_fd = lock_fd
            self._initialize_schema()
            page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
            db.execute(f"PRAGMA max_page_count={max(4, self.max_state_bytes // page_size)}")
            result = db.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise AmbientContextError("ambient context integrity check failed")
            with db:
                # A committed claim crossed the durable host-handoff boundary.
                # Retire it before reclaiming ordinary claims abandoned by the
                # previous process generation, so a crash after host acceptance
                # cannot make the same context eligible again.
                self._retire_committed_claims()
                db.execute(
                    "UPDATE facts SET claim_owner=NULL,claim_token=NULL,claimed_at=NULL "
                    "WHERE claim_token IS NOT NULL AND committed=0"
                )
                self._gc(time.time())
                self._enforce_all_bounds()
            self._checkpoint()
        except Exception as exc:
            lock_was_attached = self._lock_fd is not None
            self.close()
            if lock_fd is not None and not lock_was_attached:
                self._close_lock(lock_fd)
            if isinstance(exc, AmbientContextError):
                raise
            raise AmbientContextError("ambient context store could not be opened") from exc

    def close(self) -> None:
        db = self._db
        lock_fd = self._lock_fd
        try:
            if db is not None:
                try:
                    try:
                        with db:
                            db.execute(
                                "UPDATE facts SET claim_owner=NULL,claim_token=NULL,claimed_at=NULL "
                                "WHERE claim_owner=? AND committed=0",
                                (self.owner_id,),
                            )
                            self._gc(time.time())
                            self._enforce_all_bounds()
                    except (AmbientContextError, OSError, sqlite3.Error):
                        # Opening a corrupt/partial schema must still release the
                        # process lock without masking the original failure.
                        pass
                    try:
                        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    except sqlite3.Error:
                        pass
                finally:
                    db.close()
        finally:
            self._db = None
            self._lock_fd = None
            if lock_fd is not None:
                self._close_lock(lock_fd)

    def record(
        self,
        group_id: str,
        event_key: str,
        kind: str,
        *,
        observed_at: float | None = None,
    ) -> bool:
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
                exists = db.execute(
                    "SELECT 1 FROM facts WHERE event_key=? UNION ALL "
                    "SELECT 1 FROM seen WHERE event_key=? LIMIT 1",
                    (dedupe_key, dedupe_key),
                ).fetchone()
                if exists is not None:
                    return False
                db.execute(
                    "INSERT INTO facts(group_key,event_key,kind,observed_at) VALUES(?,?,?,?)",
                    (group_key, dedupe_key, kind, now),
                )
                self._enforce_all_bounds()
                retained = db.execute(
                    "SELECT 1 FROM facts WHERE event_key=?", (dedupe_key,)
                ).fetchone() is not None
            self._checkpoint()
            return retained
        except AmbientContextError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient fact commit failed") from exc

    def pending(self, group_id: str, *, now: float | None = None) -> list[AmbientFact]:
        """Return retained facts for diagnostics, including an active claim."""
        self.open()
        db = self._require_db()
        at = time.time() if now is None else float(now)
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                self._gc(at)
                rows = db.execute(
                    "SELECT seq,kind FROM facts WHERE group_key=? AND committed=0 ORDER BY seq",
                    (group_key,),
                ).fetchall()
            self._checkpoint()
            return [AmbientFact(int(row["seq"]), str(row["kind"])) for row in rows]
        except AmbientContextError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient facts could not be read") from exc

    def claim(self, group_id: str, *, now: float | None = None) -> AmbientClaim:
        """Atomically claim this group's currently unclaimed snapshot."""
        self.open()
        db = self._require_db()
        at = time.time() if now is None else float(now)
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        token = uuid.uuid4().hex
        try:
            with db:
                self._gc(at)
                rows = db.execute(
                    "SELECT seq,kind FROM facts WHERE group_key=? AND claim_token IS NULL ORDER BY seq",
                    (group_key,),
                ).fetchall()
                if rows:
                    ids = tuple(int(row["seq"]) for row in rows)
                    changed = db.execute(
                        f"UPDATE facts SET claim_owner=?,claim_token=?,claimed_at=? "
                        f"WHERE claim_token IS NULL AND seq IN ({','.join('?' for _ in ids)})",
                        (self.owner_id, token, at, *ids),
                    ).rowcount
                    if changed != len(ids):
                        raise AmbientContextError("ambient claim lost a compare-and-set race")
            self._checkpoint()
            return AmbientClaim(
                token,
                tuple(AmbientFact(int(row["seq"]), str(row["kind"])) for row in rows),
            )
        except AmbientContextError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient facts could not be claimed") from exc

    def acknowledge(self, group_id: str, token: str) -> int:
        """Retire one owned claim while retaining bounded replay tombstones."""
        if not token:
            return 0
        self.open()
        db = self._require_db()
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                rows = db.execute(
                    "SELECT seq,event_key,observed_at FROM facts "
                    "WHERE group_key=? AND claim_owner=? AND claim_token=? ORDER BY seq",
                    (group_key, self.owner_id, token),
                ).fetchall()
                for row in rows:
                    db.execute(
                        "INSERT OR IGNORE INTO seen(group_key,event_key,observed_at) VALUES(?,?,?)",
                        (group_key, row["event_key"], row["observed_at"]),
                    )
                changed = db.execute(
                    "DELETE FROM facts WHERE group_key=? AND claim_owner=? AND claim_token=?",
                    (group_key, self.owner_id, token),
                ).rowcount
                self._gc(time.time())
                self._enforce_all_bounds()
            self._checkpoint()
            return int(changed)
        except AmbientContextError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient acknowledgement failed") from exc

    def commit(self, group_id: str, token: str) -> int:
        """Persist that this claim crossed the host-handoff boundary.

        A normal exception or cancellation rolls this state back with
        ``release``. An abrupt process death leaves it committed, so the next
        exclusive owner retires it instead of replaying accepted context.
        """
        if not token:
            return 0
        self.open()
        db = self._require_db()
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                changed = db.execute(
                    "UPDATE facts SET committed=1 WHERE group_key=? "
                    "AND claim_owner=? AND claim_token=? AND committed=0",
                    (group_key, self.owner_id, token),
                ).rowcount
            self._checkpoint()
            return int(changed)
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient claim commit failed") from exc

    def release(self, group_id: str, token: str) -> int:
        """Release an unaccepted claim for a later eligible real turn."""
        if not token:
            return 0
        self.open()
        db = self._require_db()
        group_key = _digest(b"marmot-ambient-group-v1\0", group_id)
        try:
            with db:
                changed = db.execute(
                    "UPDATE facts SET claim_owner=NULL,claim_token=NULL,claimed_at=NULL,committed=0 "
                    "WHERE group_key=? AND claim_owner=? AND claim_token=?",
                    (group_key, self.owner_id, token),
                ).rowcount
                self._gc(time.time())
                self._enforce_all_bounds()
            self._checkpoint()
            return int(changed)
        except (OSError, sqlite3.Error) as exc:
            raise AmbientContextError("ambient claim release failed") from exc

    def stats(self) -> dict[str, int]:
        """Return privacy-safe bounded-state counters for diagnostics and tests."""
        self.open()
        db = self._require_db()
        groups = self._group_count()
        facts = int(db.execute("SELECT count(*) FROM facts").fetchone()[0])
        seen = int(db.execute("SELECT count(*) FROM seen").fetchone()[0])
        return {
            "groups": groups,
            "events": facts + seen,
            "state_bytes": self._logical_bytes(),
        }

    def _initialize_schema(self) -> None:
        db = self._require_db()
        with db:
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, 1, 2, SCHEMA_VERSION}:
                raise AmbientContextError("unsupported ambient context schema")
            db.execute(
                "CREATE TABLE IF NOT EXISTS facts("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "group_key BLOB NOT NULL,event_key BLOB NOT NULL UNIQUE,"
                "kind TEXT NOT NULL,observed_at REAL NOT NULL)"
            )
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(facts)")}
            for column, declaration in (
                ("claim_owner", "TEXT"),
                ("claim_token", "TEXT"),
                ("claimed_at", "REAL"),
                ("committed", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in columns:
                    db.execute(f"ALTER TABLE facts ADD COLUMN {column} {declaration}")
            db.execute(
                "CREATE TABLE IF NOT EXISTS seen("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "group_key BLOB NOT NULL,event_key BLOB NOT NULL UNIQUE,"
                "observed_at REAL NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS facts_group_seq ON facts(group_key,seq)")
            db.execute("CREATE INDEX IF NOT EXISTS facts_age_seq ON facts(observed_at,seq)")
            db.execute("CREATE INDEX IF NOT EXISTS seen_group_seq ON seen(group_key,seq)")
            db.execute("CREATE INDEX IF NOT EXISTS seen_age_seq ON seen(observed_at,seq)")
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _gc(self, now: float) -> None:
        db = self._require_db()
        if self.max_age_s <= 0:
            db.execute("DELETE FROM facts")
            db.execute("DELETE FROM seen")
        else:
            cutoff = now - self.max_age_s
            db.execute(
                "DELETE FROM facts WHERE observed_at<?",
                (cutoff,),
            )
            db.execute("DELETE FROM seen WHERE observed_at<?", (cutoff,))

    def _enforce_all_bounds(self) -> None:
        db = self._require_db()
        groups = db.execute(
            "SELECT group_key,count(*) FROM ("
            "SELECT group_key FROM facts UNION ALL SELECT group_key FROM seen) "
            "GROUP BY group_key"
        ).fetchall()
        for row in groups:
            group_key = row[0]
            self._delete_oldest_any(
                int(row[1]) - self.max_events_per_group,
                group_key=group_key,
            )

        while self._group_count() > self.max_groups:
            if not self._delete_oldest_aggregate_group():
                break

        total = int(
            db.execute(
                "SELECT (SELECT count(*) FROM facts)+(SELECT count(*) FROM seen)"
            ).fetchone()[0]
        )
        self._delete_oldest_any(total - self.max_events)

        while self._logical_bytes() > self.max_state_bytes:
            if not self._delete_oldest_any(1):
                break

    def _retire_committed_claims(self) -> int:
        db = self._require_db()
        rows = db.execute(
            "SELECT group_key,event_key,observed_at FROM facts WHERE committed=1 ORDER BY seq"
        ).fetchall()
        for row in rows:
            db.execute(
                "INSERT OR IGNORE INTO seen(group_key,event_key,observed_at) VALUES(?,?,?)",
                (row["group_key"], row["event_key"], row["observed_at"]),
            )
        if rows:
            db.execute("DELETE FROM facts WHERE committed=1")
        return len(rows)

    def _delete_oldest_any(self, count: int, *, group_key: bytes | None = None) -> int:
        if count <= 0:
            return 0
        db = self._require_db()
        facts_group_clause = " AND group_key=?" if group_key is not None else ""
        seen_group_clause = " WHERE group_key=?" if group_key is not None else ""
        params: list[object] = []
        if group_key is not None:
            params.extend((group_key, group_key))
        params.append(count)
        rows = db.execute(
            "SELECT source,seq FROM ("
            "SELECT 'facts' AS source,seq,observed_at FROM facts "
            f"WHERE 1=1{facts_group_clause} UNION ALL "
            f"SELECT 'seen' AS source,seq,observed_at FROM seen{seen_group_clause}) "
            "ORDER BY observed_at,source,seq LIMIT ?",
            tuple(params),
        ).fetchall()
        for row in rows:
            table = "facts" if row["source"] == "facts" else "seen"
            db.execute(f"DELETE FROM {table} WHERE seq=?", (row["seq"],))
        return len(rows)

    def _delete_oldest_aggregate_group(self) -> bool:
        db = self._require_db()
        row = db.execute(
            "SELECT group_key FROM ("
            "SELECT group_key,observed_at FROM facts UNION ALL "
            "SELECT group_key,observed_at FROM seen) candidate "
            "GROUP BY group_key ORDER BY min(observed_at),hex(group_key) LIMIT 1"
        ).fetchone()
        if row is None:
            return False
        db.execute("DELETE FROM facts WHERE group_key=?", (row[0],))
        db.execute("DELETE FROM seen WHERE group_key=?", (row[0],))
        return True

    def _delete_oldest_group(self, table: str) -> bool:
        db = self._require_db()
        if table == "facts":
            row = db.execute(
                "SELECT group_key FROM facts candidate "
                "WHERE NOT EXISTS (SELECT 1 FROM facts claimed "
                "WHERE claimed.group_key=candidate.group_key "
                "AND claimed.claim_token IS NOT NULL) "
                "GROUP BY group_key ORDER BY min(observed_at),hex(group_key) LIMIT 1"
            ).fetchone()
        elif table == "seen":
            row = db.execute(
                "SELECT group_key FROM seen GROUP BY group_key "
                "ORDER BY min(observed_at),hex(group_key) LIMIT 1"
            ).fetchone()
        else:
            raise AmbientContextError("invalid ambient context table")
        if row is None:
            return False
        db.execute(f"DELETE FROM {table} WHERE group_key=?", (row[0],))
        return True

    def _table_logical_bytes(self, table: str) -> int:
        if table == "facts":
            expression = "length(group_key)+length(event_key)+length(kind)+88"
        elif table == "seen":
            expression = "length(group_key)+length(event_key)+24"
        else:
            raise AmbientContextError("invalid ambient context table")
        row = self._require_db().execute(
            f"SELECT COALESCE(sum({expression}),0) FROM {table}"
        ).fetchone()
        return int(row[0])

    def _table_group_count(self, table: str) -> int:
        if table not in {"facts", "seen"}:
            raise AmbientContextError("invalid ambient context table")
        return int(
            self._require_db().execute(
                f"SELECT count(DISTINCT group_key) FROM {table}"
            ).fetchone()[0]
        )

    def _logical_bytes(self) -> int:
        return self._table_logical_bytes("facts") + self._table_logical_bytes("seen")

    def _group_exists(self, group_key: bytes) -> bool:
        return self._require_db().execute(
            "SELECT 1 FROM facts WHERE group_key=? UNION ALL "
            "SELECT 1 FROM seen WHERE group_key=? LIMIT 1",
            (group_key, group_key),
        ).fetchone() is not None

    def _group_count(self) -> int:
        return int(
            self._require_db().execute(
                "SELECT count(DISTINCT group_key) FROM ("
                "SELECT group_key FROM facts UNION ALL SELECT group_key FROM seen)"
            ).fetchone()[0]
        )

    def _checkpoint(self) -> None:
        db = self._require_db()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for candidate in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
            self.lock_path,
        ):
            self._chmod_private_nofollow(candidate)

    @staticmethod
    def _open_private_file(path: Path, *, create: bool = True) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise AmbientContextError("platform lacks symlink-safe file open")
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | nofollow
        if create:
            flags |= os.O_CREAT
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise AmbientContextError("ambient context file is unsafe")
            os.fchmod(fd, 0o600)
            return fd
        except Exception:
            os.close(fd)
            raise

    @classmethod
    def _chmod_private_nofollow(cls, path: Path) -> None:
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
            return
        except FileNotFoundError:
            return
        except NotImplementedError:
            pass
        except OSError as exc:
            unsupported = {errno.ENOSYS, errno.ENOTSUP}
            if hasattr(errno, "EOPNOTSUPP"):
                unsupported.add(errno.EOPNOTSUPP)
            if exc.errno not in unsupported:
                raise
        try:
            fd = cls._open_private_file(path, create=False)
        except FileNotFoundError:
            return
        os.close(fd)

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

    @staticmethod
    def _close_lock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _require_db(self) -> sqlite3.Connection:
        if self._db is None:
            raise AmbientContextError("ambient context store is not open")
        return self._db
