"""The verifier deadline must remain bounded when a prover ignores SIGTERM."""

import json
import os
from pathlib import Path
import signal
import tempfile
import unittest

from verify_pairing import check


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
                "while True: signal.pause()\n"
            )
            prover.chmod(0o700)
            model = root / "synthetic.spthy"
            model.write_text("synthetic timeout fixture; no model is evaluated\n")
            folder = root / "result"
            folder.mkdir()
            result = check(str(prover), model, folder, None, {"claim": "verified"}, 1)
            log = (folder / "prover.log").read_text()
            self.assertIn("IGNORED_SIGTERM", log, "the fixture handled the first signal")
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["termination"], "SIGKILL")
            self.assertEqual(result["exit"], -signal.SIGKILL)
            self.assertFalse(result["passed"])
            self.assertEqual(result["outcomes"], {})
            self.assertEqual(json.loads((folder / "result.json").read_text()), result)
            pid = int(log.splitlines()[0].split()[1])
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
