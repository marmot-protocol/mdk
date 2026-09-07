import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "marmot" / "ambient_context.py"
SPEC = importlib.util.spec_from_file_location("mdk_hermes_ambient_context", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load ambient context module")
ambient_context = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ambient_context
SPEC.loader.exec_module(ambient_context)
AmbientContextError = ambient_context.AmbientContextError
AmbientContextStore = ambient_context.AmbientContextStore


class AmbientContextStoreTests(unittest.TestCase):
    def test_abrupt_process_restart_preserves_private_fact_until_acknowledged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            group_id = "22" * 32
            event_id = "33" * 32
            secret_text = "message plaintext must never persist"
            script = """
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location("restart_ambient_context", os.environ["MODULE_PATH"])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
store = module.AmbientContextStore(os.environ["STORE_PATH"])
store.record(os.environ["GROUP_ID"], os.environ["EVENT_ID"], "message_deleted")
os._exit(0)
"""
            env = dict(os.environ)
            env.update(
                STORE_PATH=str(path),
                GROUP_ID=group_id,
                EVENT_ID=event_id,
                MESSAGE_TEXT=secret_text,
                MODULE_PATH=str(MODULE_PATH),
                PYTHONDONTWRITEBYTECODE="1",
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[4],
                env=env,
                check=False,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0)

            restarted = AmbientContextStore(path)
            facts = restarted.pending(group_id)
            self.assertEqual([fact.kind for fact in facts], ["message_deleted"])
            self.assertFalse(restarted.record(group_id, event_id, "message_deleted"))
            claim = restarted.claim(group_id)
            self.assertEqual(list(claim.facts), facts)
            self.assertEqual(restarted.acknowledge(group_id, claim.token), 1)
            self.assertEqual(restarted.pending(group_id), [])
            restarted.close()

            persisted = path.read_bytes()
            for forbidden in (group_id, event_id, secret_text):
                self.assertNotIn(forbidden.encode(), persisted)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_acknowledged_event_stays_deduped_across_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            group_id = "22" * 32
            event_id = "33" * 32
            store = AmbientContextStore(path)
            self.assertTrue(store.record(group_id, event_id, "message_deleted"))
            claim = store.claim(group_id)
            self.assertEqual([fact.kind for fact in claim.facts], ["message_deleted"])
            self.assertEqual(store.acknowledge(group_id, claim.token), 1)
            store.close()

            restarted = AmbientContextStore(path)
            self.assertFalse(restarted.record(group_id, event_id, "message_deleted"))
            self.assertEqual(restarted.pending(group_id), [])
            restarted.close()

    def test_abrupt_process_death_releases_claim_for_new_exclusive_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            script = """
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location("claimed_restart_ambient", os.environ["MODULE_PATH"])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
store = module.AmbientContextStore(os.environ["STORE_PATH"])
store.record("22" * 32, "event", "message_deleted")
assert store.claim("22" * 32).facts
os._exit(0)
"""
            env = dict(os.environ)
            env.update(
                STORE_PATH=str(path),
                MODULE_PATH=str(MODULE_PATH),
                PYTHONDONTWRITEBYTECODE="1",
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[4],
                env=env,
                check=False,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0)

            restarted = AmbientContextStore(path)
            claim = restarted.claim("22" * 32)
            self.assertEqual([fact.kind for fact in claim.facts], ["message_deleted"])
            restarted.close()

    def test_abrupt_death_after_handoff_commit_never_replays_accepted_fact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            script = """
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location("committed_restart_ambient", os.environ["MODULE_PATH"])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
store = module.AmbientContextStore(os.environ["STORE_PATH"])
store.record("22" * 32, "accepted-event", "message_deleted")
claim = store.claim("22" * 32)
assert store.commit("22" * 32, claim.token) == 1
os._exit(0)
"""
            env = dict(os.environ)
            env.update(
                STORE_PATH=str(path),
                MODULE_PATH=str(MODULE_PATH),
                PYTHONDONTWRITEBYTECODE="1",
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[4],
                env=env,
                check=False,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0)

            restarted = AmbientContextStore(path)
            self.assertEqual(restarted.pending("22" * 32), [])
            self.assertFalse(
                restarted.record("22" * 32, "accepted-event", "message_deleted")
            )
            restarted.close()

    def test_store_refuses_overlapping_process_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            first = AmbientContextStore(path)
            first.open()
            second = AmbientContextStore(path)
            with self.assertRaises(AmbientContextError):
                second.open()
            first.close()

    def test_claims_are_exclusive_and_release_restores_pending_fact(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AmbientContextStore(Path(directory) / "private" / "ambient.sqlite3")
            group_id = "22" * 32
            store.record(group_id, "event", "message_deleted")

            first = store.claim(group_id)
            overlapping = store.claim(group_id)
            self.assertEqual([fact.kind for fact in first.facts], ["message_deleted"])
            self.assertEqual(overlapping.facts, ())
            self.assertEqual(store.release(group_id, first.token), 1)
            retried = store.claim(group_id)
            self.assertEqual([fact.kind for fact in retried.facts], ["message_deleted"])
            store.close()

    def test_active_claim_is_retained_while_new_fact_is_refused_at_hard_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            store = AmbientContextStore(
                path,
                max_groups=1,
                max_events_per_group=1,
                max_events=1,
            )
            group_id = "22" * 32
            event_id = "first"
            store.record(group_id, event_id, "message_deleted")
            claim = store.claim(group_id)

            self.assertFalse(store.record(group_id, "second", "reaction_added"))
            self.assertLessEqual(store.stats()["events"], 1)
            self.assertEqual(store.release(group_id, claim.token), 1)
            self.assertEqual([fact.kind for fact in store.pending(group_id)], ["message_deleted"])
            store.close()

    def test_overlapping_claims_keep_group_event_byte_and_age_bounds_absolute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private"
            group_a, group_b = "aa" * 32, "bb" * 32
            store = AmbientContextStore(
                root / "bounded.sqlite3",
                max_groups=1,
                max_events_per_group=100,
                max_events=100,
                max_state_bytes=4096,
                max_age_s=10,
            )
            for index in range(12):
                store.record(group_a, f"a-{index}", "message_deleted", observed_at=100)
            claim_a = store.claim(group_a, now=100)
            self.assertTrue(claim_a.facts)

            self.assertFalse(store.record(group_b, "b-0", "reaction_added", observed_at=101))
            stats = store.stats()
            self.assertLessEqual(stats["groups"], 1)
            self.assertLessEqual(stats["events"], 100)
            self.assertLessEqual(stats["state_bytes"], 4096)

            # Active ownership preserves the claim through the in-flight turn;
            # release keeps the original observed_at, so it expires immediately
            # rather than being refreshed by claimed_at.
            self.assertEqual(len(store.pending(group_a, now=112)), 12)
            self.assertEqual(store.release(group_a, claim_a.token), 12)
            self.assertEqual(store.pending(group_a, now=112), [])
            store.close()

    def test_equal_timestamp_eviction_prefers_seen_tombstone_to_pending_fact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            store = AmbientContextStore(path, max_events=1)
            group_id = "22" * 32
            store.record(group_id, "old", "message_deleted", observed_at=100)
            claim = store.claim(group_id, now=100)
            self.assertEqual(store.acknowledge(group_id, claim.token), 1)

            self.assertTrue(store.record(group_id, "new", "reaction_added", observed_at=100))
            self.assertEqual([fact.kind for fact in store.pending(group_id, now=100)], ["reaction_added"])
            store.close()

    def test_disabled_generation_cannot_lazy_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AmbientContextStore(Path(directory) / "private" / "ambient.sqlite3")
            store.record("22" * 32, "event", "message_deleted")
            store.disable_generation()
            with self.assertRaises(AmbientContextError):
                store.pending("22" * 32)
            self.assertFalse(store.is_open)

    def test_open_reapplies_lower_configured_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            store = AmbientContextStore(path, max_events=3, max_events_per_group=3)
            for index in range(3):
                store.record("22" * 32, f"event-{index}", "message_deleted")
            store.close()

            reopened = AmbientContextStore(path, max_events=1, max_events_per_group=1)
            self.assertEqual(reopened.stats()["events"], 1)
            reopened.close()

    def test_pending_and_tombstones_share_aggregate_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AmbientContextStore(
                Path(directory) / "private" / "ambient.sqlite3",
                max_groups=3,
                max_events_per_group=3,
                max_events=3,
                max_state_bytes=4096,
            )
            for index in range(3):
                group_id = f"seen-{index}"
                store.record(group_id, f"seen-event-{index}", "message_deleted")
                claim = store.claim(group_id)
                store.acknowledge(group_id, claim.token)
            for index in range(3):
                store.record(f"pending-{index}", f"pending-event-{index}", "reaction_added")

            stats = store.stats()
            self.assertLessEqual(stats["groups"], 3)
            self.assertLessEqual(stats["events"], 3)
            self.assertLessEqual(stats["state_bytes"], 4096)
            store.close()

    def test_pending_and_tombstones_share_per_group_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AmbientContextStore(
                Path(directory) / "private" / "ambient.sqlite3",
                max_events_per_group=2,
                max_events=10,
            )
            group_id = "22" * 32
            for index in range(2):
                store.record(group_id, f"seen-{index}", "message_deleted")
                claim = store.claim(group_id)
                self.assertEqual(store.acknowledge(group_id, claim.token), 1)

            self.assertTrue(store.record(group_id, "pending-1", "message_edited"))
            self.assertTrue(store.record(group_id, "pending-2", "reaction_added"))

            self.assertEqual(
                [fact.kind for fact in store.pending(group_id)],
                ["message_edited", "reaction_added"],
            )
            self.assertEqual(store.stats()["events"], 2)
            store.close()

    def test_schema_v1_store_migrates_without_losing_pending_fact(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "private"
            parent.mkdir(mode=0o700)
            path = parent / "ambient.sqlite3"
            observed_at = ambient_context.time.time()
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE facts("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "group_key BLOB NOT NULL,event_key BLOB NOT NULL UNIQUE,"
                "kind TEXT NOT NULL,observed_at REAL NOT NULL)"
            )
            db.execute(
                "INSERT INTO facts(group_key,event_key,kind,observed_at) VALUES(?,?,?,?)",
                (
                    ambient_context._digest(b"marmot-ambient-group-v1\0", "22" * 32),
                    ambient_context._digest(b"marmot-ambient-event-v1\0", "event"),
                    "message_deleted",
                    observed_at,
                ),
            )
            db.execute("PRAGMA user_version=1")
            db.commit()
            db.close()
            path.chmod(0o600)

            migrated = AmbientContextStore(path, max_age_s=10_000)
            self.assertEqual(
                [fact.kind for fact in migrated.pending("22" * 32, now=observed_at + 1)],
                ["message_deleted"],
            )
            self.assertEqual(
                [row[1] for row in migrated._require_db().execute("PRAGMA table_info(facts)")],
                [
                    "seq",
                    "group_key",
                    "event_key",
                    "kind",
                    "observed_at",
                    "claim_owner",
                    "claim_token",
                    "claimed_at",
                    "committed",
                ],
            )
            migrated.close()

    def test_malformed_store_fails_closed_and_releases_owner_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "private"
            parent.mkdir(mode=0o700)
            path = parent / "ambient.sqlite3"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE facts(seq INTEGER PRIMARY KEY)")
            db.commit()
            db.close()
            path.chmod(0o600)

            first = AmbientContextStore(path)
            with self.assertRaises(AmbientContextError):
                first.open()
            self.assertFalse(first.is_open)

            second = AmbientContextStore(path)
            with self.assertRaises(AmbientContextError) as failure:
                second.open()
            self.assertNotIn("already owned", str(failure.exception))

    def test_permission_hardening_falls_back_when_nofollow_chmod_is_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            real_chmod = os.chmod

            def unsupported_nofollow(candidate, mode, *, dir_fd=None, follow_symlinks=True):
                if follow_symlinks is False:
                    raise NotImplementedError("follow_symlinks unavailable")
                return real_chmod(candidate, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            with mock.patch.object(os, "chmod", side_effect=unsupported_nofollow):
                store = AmbientContextStore(path)
                self.assertTrue(store.record("22" * 32, "event", "message_deleted"))
                store.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_event_group_age_and_byte_bounds_evict_oldest_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "ambient.sqlite3"
            store = AmbientContextStore(
                path,
                max_groups=2,
                max_events_per_group=2,
                max_events=3,
                max_state_bytes=4096,
                max_age_s=10,
            )
            group_a, group_b, group_c = "aa" * 32, "bb" * 32, "cc" * 32
            store.record(group_a, "a-1", "message_deleted", observed_at=100)
            store.record(group_a, "a-2", "message_edited", observed_at=101)
            store.record(group_a, "a-3", "reaction_added", observed_at=102)
            self.assertEqual(
                [fact.kind for fact in store.pending(group_a, now=102)],
                ["message_edited", "reaction_added"],
            )
            store.record(group_b, "b-1", "reaction_removed", observed_at=103)
            store.record(group_c, "c-1", "group_state:member_added", observed_at=104)
            self.assertEqual(store.pending(group_a, now=104), [])
            self.assertEqual(store.stats()["groups"], 2)
            self.assertLessEqual(store.stats()["events"], 3)
            self.assertLessEqual(store.stats()["state_bytes"], 4096)
            self.assertEqual(store.pending(group_b, now=114), [])
            store.close()

    def test_refuses_symlink_file_and_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            parent_link = root / "linked-parent"
            parent_link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(AmbientContextError):
                AmbientContextStore(parent_link / "ambient.sqlite3").open()

            private = root / "private"
            private.mkdir(mode=0o700)
            target_file = root / "target.sqlite3"
            target_file.touch(mode=0o600)
            file_link = private / "ambient.sqlite3"
            file_link.symlink_to(target_file)
            with self.assertRaises(AmbientContextError):
                AmbientContextStore(file_link).open()


if __name__ == "__main__":
    unittest.main()
