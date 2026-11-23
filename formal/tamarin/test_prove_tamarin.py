"""Contract tests for the narrow GHC RTS <<loop>> retry in formal/tamarin."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


TAMARIN_DIR = Path(__file__).resolve().parent


def write_fake_prover(root: Path, script_body: str) -> Path:
    prover = root / "fake-tamarin"
    prover.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(script_body))
    prover.chmod(0o700)
    return prover


def run_make_prove(prover: Path, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = None if extra_env is None else {**os.environ, **extra_env}
    return subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-C",
            str(TAMARIN_DIR),
            "prove",
            f"TAMARIN={prover}",
            "DERIVCHECK_TIMEOUT=42",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class TamarinProveLoopRetryTests(unittest.TestCase):
    def test_retries_once_and_recovers_on_ghc_loop_crash_without_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            args_log = root / "args"
            prover = write_fake_prover(
                root,
                """\
                import os, pathlib, sys
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                pathlib.Path(os.environ["ARGS_FILE"]).write_text(" ".join(sys.argv[1:]))
                if count == 1:
                    sys.stderr.write("[Theory distributed_convergence_v0] Theory closed\\n")
                    sys.stderr.write("tamarin-prover: <<loop>>\\n")
                    sys.exit(1)
                print("noise before summary")
                print("summary of summaries:")
                print("  demo_lemma (all-traces): verified (2 steps)")
                """,
            )
            result = run_make_prove(
                prover, {"CALLS_FILE": str(calls), "ARGS_FILE": str(args_log)}
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls.read_text(), "2")
            self.assertIn("--derivcheck-timeout=42", args_log.read_text())
            self.assertEqual(
                result.stdout,
                "summary of summaries:\n  demo_lemma (all-traces): verified (2 steps)\n",
            )
            self.assertIn("<<loop>>", result.stderr)

    def test_fails_after_single_retry_exhaustion_on_repeated_loop_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            prover = write_fake_prover(
                root,
                """\
                import os, pathlib, sys
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                sys.stderr.write("[Theory distributed_convergence_v0] Theory closed\\n")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
                """,
            )
            result = run_make_prove(prover, {"CALLS_FILE": str(calls)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls.read_text(), "2")
            self.assertIn("tamarin-prover: <<loop>>", result.stdout)

    def test_does_not_retry_when_summary_of_summaries_is_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            prover = write_fake_prover(
                root,
                """\
                import os, pathlib, sys
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                print("summary of summaries:")
                print("  demo_lemma (all-traces): verified (2 steps)")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
                """,
            )
            result = run_make_prove(prover, {"CALLS_FILE": str(calls)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls.read_text(), "1")

    def test_does_not_retry_ordinary_failure_or_falsified_lemma(self):
        for label, body, expect_ok in [
            (
                "ordinary non-zero failure",
                """\
                import os, pathlib, sys
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                sys.stderr.write("quit-on-warning mode selected - aborting\\n")
                sys.exit(1)
                """,
                False,
            ),
            (
                "falsified lemma",
                """\
                import os, pathlib
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                print("summary of summaries:")
                print("  demo_lemma (all-traces): falsified - found trace (3 steps)")
                """,
                True,
            ),
            (
                "missing summary on zero exit",
                """\
                import os, pathlib
                calls = pathlib.Path(os.environ["CALLS_FILE"])
                count = int(calls.read_text()) + 1 if calls.exists() else 1
                calls.write_text(str(count))
                print("no summary block here")
                """,
                False,
            ),
        ]:
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = root / "calls"
                prover = write_fake_prover(root, body)
                result = run_make_prove(prover, {"CALLS_FILE": str(calls)})
                self.assertEqual(result.returncode == 0, expect_ok, result.stdout + result.stderr)
                self.assertEqual(calls.read_text(), "1")


if __name__ == "__main__":
    unittest.main()
