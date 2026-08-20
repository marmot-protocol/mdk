import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("benchmark.py")
SPEC = importlib.util.spec_from_file_location("fips_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def test_probe_round_trip_is_exact_size_and_parseable(self):
        ping = benchmark.build_probe("run-1", 7, "ping", False, 512, 123)
        self.assertEqual(len(ping.encode("utf-8")), 512)
        parsed = benchmark.parse_probe(ping, "run-1")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["sequence"], 7)
        self.assertIsNone(benchmark.parse_probe(ping, "another-run"))

        parsed["kind"] = "pong"
        parsed["responder_wall_ns"] = f"{456:020d}"
        pong = benchmark.compact_json(parsed)
        self.assertEqual(len(pong.encode("utf-8")), len(ping.encode("utf-8")))

    def test_small_requested_payload_reports_the_real_minimum(self):
        probe = benchmark.build_probe("run-1", 0, "ping", True, 1, 123)
        self.assertGreater(len(probe.encode("utf-8")), 1)

    def test_percentile_uses_nearest_rank(self):
        values = [1.0, 2.0, 3.0, 4.0, 100.0]
        self.assertEqual(benchmark.percentile(values, 0.5), 3.0)
        self.assertEqual(benchmark.percentile(values, 0.95), 100.0)
        self.assertIsNone(benchmark.percentile([], 0.5))

    def test_load_successful_probes_skips_warmups_and_counts_failures(self):
        records = [
            {"schema": benchmark.SCHEMA, "event": "probe", "warmup": True,
             "outcome": "success", "round_trip_ms": 100, "publish_ack_ms": 10},
            {"schema": benchmark.SCHEMA, "event": "probe", "warmup": False,
             "outcome": "success", "round_trip_ms": 20, "publish_ack_ms": 2},
            {"schema": benchmark.SCHEMA, "event": "probe", "warmup": False,
             "outcome": "timeout", "round_trip_ms": None, "publish_ack_ms": None},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records))
            round_trips, publish_acks, failures = benchmark.load_successful_probes(
                [str(path)]
            )
        self.assertEqual(round_trips, [20.0])
        self.assertEqual(publish_acks, [2.0])
        self.assertEqual(failures, 1)


if __name__ == "__main__":
    unittest.main()
