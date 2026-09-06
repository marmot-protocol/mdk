import importlib.util
import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


MODULE_PATH = Path(__file__).resolve().parents[2] / "marmot" / "inbound_spool.py"
SPEC = importlib.util.spec_from_file_location("mdk_hermes_inbound_spool", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load inbound spool module")
spool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = spool
SPEC.loader.exec_module(spool)


def event(index: int, *, group: str = "22"):
    message_id = f"{index:064x}"
    return {
        "type": "inbound_message",
        "account_id_hex": "11" * 32,
        "group_id_hex": group * 32,
        "message_id_hex": message_id,
        "sender_account_id_hex": "33" * 32,
        "sender_display_name": "Alice",
        "text": f"private payload {index}",
        "recorded_at": index,
        "mentions_self": True,
        "media": [],
    }


def wait_for(path: Path, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError("child did not reach crash point")


class InboundSpoolTests(unittest.TestCase):
    def test_record_reopen_and_private_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private" / "spool.sqlite3"
            store = spool.InboundSpool(path)
            self.assertEqual({"reclaimed": 0, "unresolved": 0}, store.open())
            inserted, state = store.record(event(1))
            self.assertTrue(inserted)
            self.assertEqual("pending", state)
            self.assertEqual("private payload 1", store.get(event(1)["message_id_hex"]).event["text"])
            self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(0o600, Path(f"{path}-wal").stat().st_mode & 0o777)
            store.close()
            reopened = spool.InboundSpool(path)
            reopened.open()
            self.assertEqual("pending", reopened.get(event(1)["message_id_hex"]).state)
            reopened.close()

    def test_generation_reclaims_claim_but_never_replays_unknown_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spool.sqlite3"
            first = spool.InboundSpool(path)
            first.open()
            first.record(event(1))
            first.claim(event(1)["message_id_hex"])
            first.close(graceful=False)
            second = spool.InboundSpool(path)
            self.assertEqual({"reclaimed": 1, "unresolved": 0}, second.open())
            self.assertEqual("pending", second.get(event(1)["message_id_hex"]).state)
            second.claim(event(1)["message_id_hex"])
            second.transition(event(1)["message_id_hex"], "handed", "host_handoff_started")
            second.close(graceful=False)
            third = spool.InboundSpool(path)
            self.assertEqual({"reclaimed": 0, "unresolved": 1}, third.open())
            record = third.get(event(1)["message_id_hex"])
            self.assertEqual("unresolved", record.state)
            self.assertEqual([], third.due())
            third.close()

    def test_coalescing_retains_all_ids_payload_and_effective_reply_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = spool.InboundSpool(Path(tmp) / "spool.sqlite3")
            store.open()
            first, second = event(1), event(2)
            second["reply_to"] = {"message_id_hex": "aa" * 32, "availability": "missing"}
            store.record(first)
            store.record(second)
            merged = dict(second)
            merged["text"] = "private payload 1\nprivate payload 2"
            representative = store.form_batch(
                [first["message_id_hex"], second["message_id_hex"]], merged
            )
            self.assertEqual(first["message_id_hex"], representative)
            rep = store.get(representative)
            self.assertEqual((first["message_id_hex"], second["message_id_hex"]), rep.source_ids)
            self.assertEqual("aa" * 32, rep.reply_anchor)
            self.assertEqual(merged["text"], rep.event["text"])
            self.assertEqual("coalesced", store.get(second["message_id_hex"]).state)
            self.assertEqual(representative, store.claim(representative).message_id)
            store.transition(representative, "intentionally_skipped", "mention_policy_skip")
            coalesced = store.get(second["message_id_hex"])
            self.assertEqual("intentionally_skipped", coalesced.state)
            self.assertEqual(
                "coalesced_mention_policy_skip",
                coalesced.disposition,
            )
            store.close()

    def test_debounce_buffered_rows_are_inadmissible_until_batched_or_recovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spool.sqlite3"
            store = spool.InboundSpool(path)
            store.open()
            first, second = event(1), event(2)
            store.record(first, debounce_buffered=True)
            store.record(second, debounce_buffered=True)

            self.assertEqual([], store.due())
            with self.assertRaises(spool.StaleClaim):
                store.claim(first["message_id_hex"])

            merged = dict(second)
            merged["text"] = "private payload 1\nprivate payload 2"
            representative = store.form_batch(
                [first["message_id_hex"], second["message_id_hex"]], merged
            )
            self.assertEqual(first["message_id_hex"], representative)
            self.assertEqual(representative, store.claim(representative).message_id)
            store.close(graceful=False)

            recovery_path = Path(tmp) / "recovery.sqlite3"
            crashed = spool.InboundSpool(recovery_path)
            crashed.open()
            crashed.record(first, debounce_buffered=True)
            crashed.close(graceful=False)
            reopened = spool.InboundSpool(recovery_path)
            reopened.open()
            self.assertEqual(
                [first["message_id_hex"]],
                [record.message_id for record in reopened.due()],
            )
            reopened.close()

    def test_per_group_fifo_blocks_newer_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = spool.InboundSpool(Path(tmp) / "spool.sqlite3")
            store.open()
            store.record(event(1))
            store.record(event(2))
            with self.assertRaises(spool.StaleClaim):
                store.claim(event(2)["message_id_hex"])
            store.claim(event(1)["message_id_hex"])
            store.transition(event(1)["message_id_hex"], "handed", "host_handoff_started")
            self.assertEqual(event(2)["message_id_hex"], store.claim(event(2)["message_id_hex"]).message_id)
            store.close()

    def test_capacity_never_evicts_pending(self):
        with self.assertRaisesRegex(ValueError, "at least 1 MiB"):
            spool.InboundSpool(Path("unused.sqlite3"), max_bytes=1024)
        with tempfile.TemporaryDirectory() as tmp:
            store = spool.InboundSpool(Path(tmp) / "spool.sqlite3", max_pending=1, max_bytes=1024 * 1024)
            store.open()
            store.record(event(1))
            with self.assertRaises(spool.SpoolFullError):
                store.record(event(2))
            self.assertEqual("pending", store.get(event(1)["message_id_hex"]).state)
            store.close()

    def test_transaction_mode_rolls_back_partial_batch_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = spool.InboundSpool(Path(tmp) / "spool.sqlite3")
            store.open()
            first, second = event(1), event(2)
            store.record(first)
            store.record(second)
            with self.assertRaises(RuntimeError):
                with store._db:
                    store._db.execute(
                        "UPDATE events SET event_json=? WHERE message_id=?",
                        (json.dumps({"partial": True}), first["message_id_hex"]),
                    )
                    raise RuntimeError("simulated process fault before batch commit")
            self.assertEqual(first["text"], store.get(first["message_id_hex"]).event["text"])
            self.assertEqual("pending", store.get(second["message_id_hex"]).state)
            store.close()

    def test_corrupt_or_newer_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spool.sqlite3"
            path.write_bytes(b"not sqlite")
            path.chmod(0o600)
            with self.assertRaises(spool.InboundSpoolError):
                spool.InboundSpool(path).open()
            self.assertEqual(b"not sqlite", path.read_bytes())

    def test_live_owner_lock_prevents_duplicate_execution_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spool.sqlite3"
            owner = spool.InboundSpool(path)
            owner.open()
            contender = spool.InboundSpool(path)
            with self.assertRaises(spool.SpoolLockedError):
                contender.open()
            owner.close()

    def test_real_process_sigkill_crash_windows(self):
        for crash_state, expected in (
            ("recorded", "pending"),
            ("claimed", "pending"),
            ("handed", "unresolved"),
        ):
            with self.subTest(crash_state=crash_state), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "spool.sqlite3"
                marker = Path(tmp) / "ready"
                child = subprocess.Popen(
                    [sys.executable, __file__, "--crash-child", str(path), str(marker), crash_state]
                )
                wait_for(marker)
                os.kill(child.pid, signal.SIGKILL)
                self.assertEqual(-signal.SIGKILL, child.wait(timeout=5))
                probe = subprocess.run(
                    [sys.executable, __file__, "--probe", str(path)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                result = json.loads(probe.stdout)
                self.assertEqual(expected, result["state"])
                self.assertEqual("private payload 1", result["text"])

    def test_real_adapter_process_crash_windows(self):
        for crash_point, expected_pending in (
            ("before_claim", 1),
            ("queued_before_dispatch", 1),
            ("inside_debounce", 2),
        ):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "spool.sqlite3"
                marker = Path(tmp) / "ready"
                child = subprocess.Popen(
                    [
                        sys.executable,
                        __file__,
                        "--adapter-crash-child",
                        str(path),
                        str(marker),
                        crash_point,
                    ]
                )
                wait_for(marker)
                os.kill(child.pid, signal.SIGKILL)
                self.assertEqual(-signal.SIGKILL, child.wait(timeout=5))
                probe_result = subprocess.run(
                    [sys.executable, __file__, "--probe-all", str(path)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                result = json.loads(probe_result.stdout)
                self.assertEqual(expected_pending, result["counts"].get("pending", 0))
                self.assertEqual(expected_pending, len(result["texts"]))


def crash_child(path: Path, marker: Path, state: str):
    store = spool.InboundSpool(path)
    store.open()
    item = event(1)
    store.record(item)
    if state in {"claimed", "handed"}:
        store.claim(item["message_id_hex"])
    if state == "handed":
        store.transition(item["message_id_hex"], "handed", "host_handoff_started")
    marker.write_text("ready")
    while True:
        time.sleep(1)


async def adapter_crash_child(path: Path, marker: Path, point: str):
    # Reuse the repository's fake Hermes surface while exercising the real
    # adapter/spool integration in a separately killable process.
    sys.path.insert(0, str(Path(__file__).parent))
    import test_adapter

    module = test_adapter.load_adapter_module()
    config_cls = sys.modules["gateway.config"].PlatformConfig
    extra = {
        "account_id_hex": "11" * 32,
        "group_activation": "always",
        "profile_name_onboarding": False,
    }
    if point == "inside_debounce":
        extra["debounce_ms"] = 60_000
    config = config_cls(extra=extra)
    config._inbound_spool_test_path = str(path)
    adapter = module.MarmotPlatformAdapter(config, client=object())

    if point == "before_claim":
        def stop_before_claim(message_id, **_kwargs):
            marker.write_text("ready")
            while True:
                time.sleep(1)

        adapter._inbound_spool.claim = stop_before_claim
    elif point == "queued_before_dispatch":
        async def stop_before_dispatch(*args, **kwargs):
            marker.write_text("ready")
            while True:
                await asyncio.sleep(1)

        adapter._dispatch_inbound_message = stop_before_dispatch

    await adapter._handle_control_event(test_adapter.wire_event(event(1)))
    if point == "inside_debounce":
        await adapter._handle_control_event(test_adapter.wire_event(event(2)))
        marker.write_text("ready")
    while True:
        await asyncio.sleep(1)


def probe(path: Path):
    store = spool.InboundSpool(path)
    store.open()
    item = store.get(event(1)["message_id_hex"])
    print(json.dumps({"state": item.state, "text": item.event["text"]}))
    store.close()


def probe_all(path: Path):
    store = spool.InboundSpool(path)
    store.open()
    items = [store.get(event(index)["message_id_hex"]) for index in (1, 2)]
    print(json.dumps({
        "counts": store.snapshot(),
        "texts": [item.event["text"] for item in items if item is not None],
    }))
    store.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--crash-child":
        crash_child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    elif len(sys.argv) > 1 and sys.argv[1] == "--probe":
        probe(Path(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] == "--adapter-crash-child":
        asyncio.run(adapter_crash_child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]))
    elif len(sys.argv) > 1 and sys.argv[1] == "--probe-all":
        probe_all(Path(sys.argv[2]))
    else:
        unittest.main()
