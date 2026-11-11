#!/usr/bin/env python3
"""Regression tests for the test timing ratchet."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import check_test_timing_ratchet as ratchet


def waits(path: str, source: str) -> dict[str, int]:
    return ratchet.count_waits(path, textwrap.dedent(source))


class CountWaitsTests(unittest.TestCase):
    def test_counts_free_sleep_calls_and_short_timeouts(self):
        self.assertEqual(waits("crates/a/tests/flow.rs", """\
            async fn flow() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                std::thread::sleep(SETTLE);
                sleep(Duration::from_secs(2)).await;
                timeout(Duration::from_millis(500), ready).await.unwrap();
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    ready,
                ).await.unwrap();
                timeout(Duration::from_secs_f64(0.25), ready).await.unwrap();
                timeout(Duration::from_millis(500_u64), ready).await.unwrap();
                timeout(Duration::from_millis(500,), ready).await.unwrap();
                timeout(Duration::from_secs_f64(1e-3), ready).await.unwrap();
                timeout(Duration::from_secs_f64(2.5E+1), ready).await.unwrap();
            }
        """), {"sleep": 3, "short_timeout": 6})

    def test_ignores_long_timeouts_methods_definitions_comments_and_strings(self):
        self.assertEqual(waits("crates/a/src/tests.rs", """\
            fn sleep(duration: Duration) {}
            async fn flow(clock: &Clock) {
                clock.sleep(Duration::from_secs(1));
                timeout(Duration::from_secs(5), ready).await.unwrap();
                timeout(Duration::from_millis(1_500), ready).await.unwrap();
                timeout(BOUND, ready).await.unwrap();
                timeout(Duration::from_secs(1) * 30, ready).await.unwrap();
                recv_timeout(Duration::from_millis(10));
                // sleep(Duration::from_millis(5));
                /* sleep(1) /* nested */ sleep(2) */
                let script = "sleep(1); timeout(Duration::from_millis(5), x)";
                let raw = r#"sleep("1")"#;
                let brace = '{';
                let _: &'static str = "}";
            }
        """), {})

    def test_paused_time_functions_do_not_count(self):
        self.assertEqual(waits("crates/a/tests/paused.rs", """\
            #[tokio::test(flavor = "current_thread", start_paused = true)]
            async fn paused_by_attribute() {
                tokio::time::sleep(Duration::from_secs(60)).await;
                timeout(Duration::from_millis(5), ready).await.unwrap();
            }

            #[tokio::test]
            async fn paused_by_call() {
                tokio::time::pause();
                if ready { tokio::time::sleep(Duration::from_secs(60)).await; }
            }

            #[tokio::test]
            async fn real_time() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            #[tokio::test(start_paused = true)]
            async fn blocks_the_thread_anyway() {
                std::thread::sleep(Duration::from_millis(5));
            }

            #[tokio::test(start_paused = true)]
            async fn starts_paused_then_resumes() {
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::time::resume();
                timeout(Duration::from_millis(10), ready).await.unwrap();
            }

            #[tokio::test]
            async fn resumed() {
                tokio::time::pause();
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::time::resume();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        """), {"sleep": 3, "short_timeout": 1})
        # Imported names: a bare `pause()` pauses, and an imported
        # `std::thread::sleep` still blocks on paused time.
        self.assertEqual(waits("crates/a/tests/imported.rs", """            use tokio::time::{pause, sleep as tokio_sleep, timeout};

            #[tokio::test]
            async fn paused_by_imported_call() {
                pause();
                timeout(Duration::from_millis(5), ready).await.unwrap();
            }
        """), {})
        self.assertEqual(waits("crates/a/tests/blocking.rs", """            use std::thread::sleep;

            #[tokio::test(start_paused = true)]
            async fn blocks_the_thread_anyway() {
                sleep(Duration::from_millis(5));
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        """), {"sleep": 1})

    def test_only_test_code_counts(self):
        production = """\
            async fn run() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            #[cfg(test)]
            mod tests {
                #[tokio::test]
                async fn waits() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        """
        self.assertEqual(waits("crates/a/src/lib.rs", production), {"sleep": 1})
        self.assertEqual(waits("crates/a/src/lib.rs", """\
            #[test]
            fn top_level_test() { std::thread::sleep(Duration::from_millis(5)); }

            #[cfg(test)]
            pub(crate) async fn test_helper() { tokio::time::sleep(Duration::from_millis(5)).await; }

            #[cfg(test)]
            const SETTLE: u64 = 5;
            fn production() { std::thread::sleep(Duration::from_millis(SETTLE)); }

            #[cfg(test)]
            impl Hold {
                fn settle(&self) { std::thread::sleep(Duration::from_millis(5)); }
                async fn wait(&self) { timeout(Duration::from_millis(500), self.ready()).await.unwrap(); }
            }

            impl Production {
                fn settle(&self) { std::thread::sleep(Duration::from_millis(5)); }
            }
        """), {"sleep": 3, "short_timeout": 1})
        gated = production.replace("#[cfg(test)]", "#[cfg(all(test, unix))]")
        self.assertEqual(waits("crates/a/src/lib.rs", gated), {"sleep": 1})
        nested = production.replace("#[cfg(test)]", "#[cfg(all(test, any(unix, windows)))]").replace(
            "#[tokio::test]", "")
        self.assertEqual(waits("crates/a/src/lib.rs", nested), {"sleep": 1})
        not_test = production.replace("#[cfg(test)]", "#[cfg(all(not(test), unix))]").replace("#[tokio::test]", "")
        self.assertEqual(waits("crates/a/src/lib.rs", not_test), {})
        for path in ["crates/a/tests/x.rs", "crates/a/src/tests.rs", "crates/a/src/worker_tests.rs",
                     "crates/a/src/runtime/tests/x.rs", "crates/a/src/test_support.rs",
                     "crates/a/src/test_support/relay.rs"]:
            with self.subTest(path=path):
                self.assertEqual(waits(path, production), {"sleep": 2})


class RatchetTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.baseline = self.root / "baseline.json"
        self.write("crates/a/tests/old.rs", 2)
        ratchet.write_baseline(self.baseline, {"crates/a/tests/old.rs": {"sleep": 2}})

    def write(self, path: str, sleeps: int) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("fn t() {\n" + "    std::thread::sleep(D);\n" * sleeps + "}\n")

    def main(self, *args: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = ratchet.main(list(args), root=self.root, baseline_path=self.baseline)
        self.stderr = err.getvalue()
        return code

    def recorded(self) -> dict:
        return json.loads(self.baseline.read_text())["files"]

    def test_out_of_line_test_modules_count_with_their_children(self):
        def source(path, text):
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text(textwrap.dedent(text))

        wait = "fn helper() { std::thread::sleep(D); }\n"
        source("crates/b/src/lib.rs", """\
            pub mod runtime;
            #[cfg(test)]
            mod boundary;
            #[cfg(all(test, unix))]
            #[path = "probes/acquire.rs"]
            mod acquisition;
        """)
        source("crates/b/src/runtime.rs", textwrap.dedent("""\
            #[cfg(all(test, any(unix, windows)))]
            mod scale;
            #[cfg(test)]
            mod outer {
                #[path = "probe.rs"]
                mod inner;
            }
        """) + wait)
        source("crates/b/src/runtime/outer/probe.rs", wait)
        source("crates/b/src/runtime/scale.rs", "mod nested;\n" + wait)
        source("crates/b/src/runtime/scale/nested.rs", wait)
        source("crates/b/src/boundary/mod.rs", wait)
        source("crates/b/src/probes/acquire.rs", wait)
        counts = ratchet.scan(self.root)
        self.assertEqual(sorted(path for path in counts if path.startswith("crates/b/")), [
            "crates/b/src/boundary/mod.rs", "crates/b/src/probes/acquire.rs",
            "crates/b/src/runtime/outer/probe.rs", "crates/b/src/runtime/scale.rs",
            "crates/b/src/runtime/scale/nested.rs"])

    def test_unchanged_and_lower_counts_pass(self):
        self.assertEqual(self.main(), 0)
        self.write("crates/a/tests/old.rs", 1)
        self.assertEqual(self.main(), 0)
        self.assertEqual(self.recorded(), {"crates/a/tests/old.rs": {"sleep": 2}})

    def test_a_rise_or_a_new_file_with_waits_fails(self):
        self.write("crates/a/tests/old.rs", 3)
        self.assertEqual(self.main(), 1)
        self.assertIn("crates/a/tests/old.rs: sleep calls 2 -> 3", self.stderr)
        self.write("crates/a/tests/old.rs", 2)
        self.write("crates/a/tests/new.rs", 1)
        self.assertEqual(self.main(), 1)
        self.assertIn("--allow-increase", self.stderr)

    def test_update_records_decreases_but_needs_allow_increase_for_rises(self):
        self.write("crates/a/tests/old.rs", 1)
        self.write("crates/a/tests/new.rs", 1)
        self.assertEqual(self.main("--update"), 1)
        self.assertEqual(self.recorded(), {"crates/a/tests/old.rs": {"sleep": 2}})
        self.assertEqual(self.main("--update", "--allow-increase"), 0)
        self.assertEqual(self.recorded(), {"crates/a/tests/new.rs": {"sleep": 1},
                                           "crates/a/tests/old.rs": {"sleep": 1}})
        self.write("crates/a/tests/new.rs", 0)
        self.assertEqual(self.main("--update"), 0)
        self.assertEqual(self.recorded(), {"crates/a/tests/old.rs": {"sleep": 1}})


if __name__ == "__main__":
    unittest.main()
