"""The verifier deadline must remain bounded when a prover ignores SIGTERM."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from verify_pairing import check


COUNTER_PREAMBLE = """\
#!/usr/bin/env python3
import os, pathlib, sys
calls = pathlib.Path(os.environ["CALLS_FILE"])
count = int(calls.read_text()) + 1 if calls.exists() else 1
calls.write_text(str(count))
"""


def write_fake_prover(root: Path, script_body: str) -> Path:
    prover = root / "fake-prover"
    prover.write_text(COUNTER_PREAMBLE + textwrap.dedent(script_body))
    prover.chmod(0o700)
    return prover


class PairingVerifierDeadline(unittest.TestCase):
    def test_unresponsive_prover_is_killed_reaped_and_never_counted_as_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prover = root / "unresponsive-prover"
            prover.write_text(
                "#!/usr/bin/env python3\n"
                "import os, signal\n"
                "def ignore_term(signum, frame):\n"
                "    print('IGNORED_SIGTERM', flush=True)\n"
                "signal.signal(signal.SIGTERM, ignore_term)\n"
                "print('READY', os.getpid(), flush=True)\n"
                "os.write(int(os.environ['MDK_TEST_READY_FD']), b'R')\n"
                "while True: signal.pause()\n"
            )
            prover.chmod(0o700)
            model = root / "synthetic.spthy"
            model.write_text("synthetic timeout fixture; no model is evaluated\n")
            folder = root / "result"
            folder.mkdir()
            ready_read, ready_write = os.pipe()
            real_popen = subprocess.Popen

            def launch_ready(*args, **kwargs):
                # Only synchronize fixture startup. All process operations and
                # statuses still come from this real, unmodified Popen object.
                kwargs["pass_fds"] = (ready_write,)
                kwargs["env"] = {**os.environ, "MDK_TEST_READY_FD": str(ready_write)}
                child = real_popen(*args, **kwargs)
                try:
                    readable, _, _ = select.select([ready_read], [], [], 10)
                    self.assertTrue(readable, "fixture did not install its signal handler")
                    self.assertEqual(os.read(ready_read, 1), b"R")
                    return child
                except BaseException:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)
                    raise

            try:
                with patch("verify_pairing.subprocess.Popen", side_effect=launch_ready):
                    result = check(str(prover), model, folder, None, {"claim": "verified"}, 1)
            finally:
                os.close(ready_read)
                os.close(ready_write)
            log = (folder / "prover.log").read_text()
            self.assertIn("IGNORED_SIGTERM", log, "the fixture handled the first signal")
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["termination"], "SIGKILL")
            self.assertEqual(result["exit"], -signal.SIGKILL)
            self.assertFalse(result["passed"])
            self.assertEqual(result["attempts"], 1)
            self.assertEqual(result["outcomes"], {})
            self.assertEqual(json.loads((folder / "result.json").read_text()), result)
            pid = int(log.splitlines()[0].split()[1])
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class PairingVerifierLoopRetry(unittest.TestCase):
    def run_check(self, script_body: str, expected: dict[str, str], timeout: int = 10):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            prover = write_fake_prover(root, script_body)
            model = root / "synthetic.spthy"
            model.write_text("synthetic loop-retry fixture\n")
            folder = root / "result"
            folder.mkdir()
            with patch.dict(os.environ, {"CALLS_FILE": str(calls)}):
                result = check(str(prover), model, folder, None, expected, timeout)
            return result, int(calls.read_text()), (folder / "prover.log").read_text()

    def test_retries_once_and_recovers_on_ghc_loop_crash_without_summary(self):
        result, attempts, log = self.run_check(
            """\
            if count == 1:
                sys.stderr.write("[Theory DevicePairingV1] Theory closed\\n")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
            print("summary of summaries:")
            print("  claim (all-traces): verified (2 steps)")
            """,
            {"claim": "verified"},
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["exit"], 0)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(attempts, 2)
        self.assertEqual(result["outcomes"], {"claim": "verified (2 steps)"})
        self.assertNotIn("<<loop>>", log)

    def test_fails_after_retry_exhaustion_on_repeated_loop_crash(self):
        result, attempts, log = self.run_check(
            """\
            sys.stderr.write("[Theory DevicePairingV1] Theory closed\\n")
            sys.stderr.write("tamarin-prover: <<loop>>\\n")
            sys.exit(1)
            """,
            {"claim": "verified"},
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["exit"], 1)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(attempts, 2)
        self.assertIn("tamarin-prover: <<loop>>", log)

    def test_retry_shares_single_check_deadline_and_skips_when_exhausted(self):
        script = """\
            if count == 1:
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
            print("summary of summaries:")
            print("  claim (all-traces): verified (2 steps)")
            """
        # Case 1: first attempt crashes at t=6 under a 10s budget -> retry gets 4s, not 10s.
        wait_timeouts: list[float | None] = []
        real_popen = subprocess.Popen

        class RecordingPopen(real_popen):
            def wait(self, timeout=None):
                wait_timeouts.append(timeout)
                return super().wait(timeout=timeout)

        # monotonic calls: start(0), attempt1 remaining(0), retry check(6), attempt2 remaining(6), elapsed(8)
        with patch("verify_pairing.time.monotonic", side_effect=[0.0, 0.0, 6.0, 6.0, 8.0]), \
             patch("verify_pairing.subprocess.Popen", RecordingPopen):
            result, attempts, _ = self.run_check(script, {"claim": "verified"}, timeout=10)
        self.assertTrue(result["passed"])
        self.assertEqual(attempts, 2)
        self.assertEqual(wait_timeouts, [10.0, 4.0])

        # Case 2: first attempt crashes at t=10 under a 10s budget -> no retry starts.
        with patch("verify_pairing.time.monotonic", side_effect=[0.0, 0.0, 10.0, 10.0]):
            result, attempts, _ = self.run_check(script, {"claim": "verified"}, timeout=10)
        self.assertFalse(result["passed"])
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(attempts, 1)

    def test_does_not_retry_falsified_lemma_or_post_summary_failure(self):
        for label, body, expected_exit in [
            (
                "summary present with loop",
                """\
                print("summary of summaries:")
                print("  claim (all-traces): verified (2 steps)")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
                """,
                1,
            ),
            (
                "falsified lemma",
                """\
                print("summary of summaries:")
                print("  claim (all-traces): falsified - found trace (4 steps)")
                """,
                0,
            ),
        ]:
            with self.subTest(label):
                result, attempts, _ = self.run_check(body, {"claim": "verified"})
                self.assertFalse(result["passed"])
                self.assertEqual(result["exit"], expected_exit)
                self.assertEqual(result["attempts"], 1)
                self.assertEqual(attempts, 1)


if __name__ == "__main__":
    unittest.main()
