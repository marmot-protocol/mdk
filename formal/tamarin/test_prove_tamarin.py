"""Contract tests for the narrow GHC RTS <<loop>> retry in formal/tamarin."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

from prove_tamarin import is_ghc_loop_crash


TAMARIN_DIR = Path(__file__).resolve().parent

COUNTER_PREAMBLE = """\
#!/usr/bin/env python3
import os, pathlib, sys
calls = pathlib.Path(os.environ["CALLS_FILE"])
count = int(calls.read_text()) + 1 if calls.exists() else 1
calls.write_text(str(count))
"""


def write_fake_prover(root: Path, script_body: str) -> Path:
    prover = root / "fake-tamarin"
    prover.write_text(COUNTER_PREAMBLE + textwrap.dedent(script_body))
    prover.chmod(0o700)
    return prover


def run_make_prove(
    tamarin_arg: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = None if extra_env is None else {**os.environ, **extra_env}
    return subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-C",
            str(TAMARIN_DIR),
            "prove",
            f"TAMARIN={tamarin_arg}",
            "DERIVCHECK_TIMEOUT=42",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class LoopCrashPredicateTests(unittest.TestCase):
    def test_predicate_matches_only_pre_summary_positive_exit_loop_line(self):
        cases = [
            ("clean loop crash", 1, "[Theory x] Theory closed\ntamarin-prover: <<loop>>\n", True),
            ("prefixed loop line", 1, "  // tamarin-prover: <<loop>>\n", False),
            ("signal exit", -9, "tamarin-prover: <<loop>>\n", False),
            ("zero exit", 0, "tamarin-prover: <<loop>>\n", False),
            ("none status", None, "tamarin-prover: <<loop>>\n", False),
            (
                "summary already printed",
                1,
                "summary of summaries:\ntamarin-prover: <<loop>>\n",
                False,
            ),
            ("ordinary failure", 1, "quit-on-warning mode selected\n", False),
        ]
        for label, status, output, expected in cases:
            with self.subTest(label):
                self.assertEqual(is_ghc_loop_crash(status, output), expected)


class TamarinProveLoopRetryTests(unittest.TestCase):
    def test_retries_once_and_recovers_on_ghc_loop_crash_without_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            args_log = root / "args"
            prover = write_fake_prover(
                root,
                """\
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
                f"env PROVE_WRAPPER=1 {prover}",
                {"CALLS_FILE": str(calls), "ARGS_FILE": str(args_log)},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls.read_text(), "2")
            self.assertIn("--derivcheck-timeout=42", args_log.read_text())
            self.assertEqual(
                result.stdout,
                "summary of summaries:\n  demo_lemma (all-traces): verified (2 steps)\n",
            )
            self.assertIn("[Theory distributed_convergence_v0] Theory closed", result.stderr)
            self.assertIn("tamarin-prover: <<loop>>", result.stderr)

    def test_fails_after_single_retry_exhaustion_on_repeated_loop_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            prover = write_fake_prover(
                root,
                """\
                sys.stderr.write("[Theory distributed_convergence_v0] Theory closed\\n")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
                """,
            )
            result = run_make_prove(str(prover), {"CALLS_FILE": str(calls)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls.read_text(), "2")
            self.assertIn("tamarin-prover: <<loop>>", result.stdout)

    def test_does_not_retry_when_summary_is_present_or_on_non_loop_outcomes(self):
        for label, body, expect_ok in [
            (
                "summary present with loop",
                """\
                print("summary of summaries:")
                print("  demo_lemma (all-traces): verified (2 steps)")
                sys.stderr.write("tamarin-prover: <<loop>>\\n")
                sys.exit(1)
                """,
                False,
            ),
            (
                "ordinary non-zero failure",
                """\
                sys.stderr.write("quit-on-warning mode selected - aborting\\n")
                sys.exit(1)
                """,
                False,
            ),
            (
                "falsified lemma",
                """\
                print("summary of summaries:")
                print("  demo_lemma (all-traces): falsified - found trace (3 steps)")
                """,
                True,
            ),
            (
                "missing summary on zero exit",
                """\
                print("no summary block here")
                """,
                False,
            ),
        ]:
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = root / "calls"
                prover = write_fake_prover(root, body)
                result = run_make_prove(str(prover), {"CALLS_FILE": str(calls)})
                self.assertEqual(result.returncode == 0, expect_ok, result.stdout + result.stderr)
                self.assertEqual(calls.read_text(), "1")


if __name__ == "__main__":
    unittest.main()
