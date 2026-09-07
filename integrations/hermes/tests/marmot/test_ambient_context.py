import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


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
            self.assertEqual(restarted.acknowledge(group_id, [facts[0].seq]), 1)
            self.assertEqual(restarted.pending(group_id), [])
            restarted.close()

            persisted = path.read_bytes()
            for forbidden in (group_id, event_id, secret_text):
                self.assertNotIn(forbidden.encode(), persisted)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

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
