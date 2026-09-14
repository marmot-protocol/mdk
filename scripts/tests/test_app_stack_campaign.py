"""Campaign selection and failure handling without building the Rust workspace."""
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("campaign", Path(__file__).resolve().parents[1] / "app_stack_campaign.py")
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class CampaignTests(unittest.TestCase):
    def test_process_canary_uses_the_preserved_production_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = {"id": "process-canary", "kind": "test", "binary": "app_generated_variance",
                    "command": ["test-binary"], "timeout": 1200}

            def fake_run(_command, directory, env, _timeout):
                self.assertEqual(env["MDK_APP_PROCESS_NODE"], str(root / "bin" / "cgka-conformance-node"))
                self.assertEqual(env["MDK_SCENARIO_NODE_BIN"], str(root / "bin" / "cgka-conformance-node"))
                (directory / "output.log").write_text("test result: ok. 1 passed; 0 failed; 0 ignored;")
                return {"exit_code": 0, "timed_out": False}

            with patch.object(campaign, "run_command", side_effect=fake_run):
                self.assertTrue(campaign.execute(task, root, {})["passed"])

    def test_incidental_compatibility_artifacts_do_not_replace_release_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            names = (*campaign.TEST_BINARIES, "cgka-conformance-campaign", "cgka-conformance-node")

            def fake_build(_command, directory, _env, _timeout):
                index = int(directory.name.removeprefix("build-"))
                messages = []
                for name in names:
                    artifact = directory / name
                    artifact.write_text(f"{index}:{name}")
                    messages.append({"reason": "compiler-artifact", "target": {"name": name},
                                     "executable": str(artifact), "features": []})
                (directory / "output.log").write_text("\n".join(map(json.dumps, messages)))
                return {"exit_code": 0}

            with patch.object(campaign, "run_command", side_effect=fake_build):
                executables = campaign.build(root, {})
            for name, path in executables.items():
                index = 0 if name in ("cgka-conformance-campaign", "cgka-conformance-node") else 2 if name == "process_orchestrator" else 1
                self.assertEqual(Path(path).read_text(), f"{index}:{name}")

    def test_legacy_comparison_has_a_separate_optimized_compatibility_build(self):
        generated, public_tests, control = campaign.build_commands()
        self.assertNotIn("--config", generated)
        self.assertNotIn("--config", public_tests)
        self.assertNotIn("process_orchestrator", public_tests)
        self.assertEqual(control[control.index("--test") + 1:], ["process_orchestrator"])
        self.assertIn("--release", control)
        self.assertIn("--locked", control)
        self.assertNotIn("--features", control)
        overrides = [control[index + 1] for index, arg in enumerate(control) if arg == "--config"]
        self.assertEqual(overrides, [
            "profile.release.package.cgka-engine.debug-assertions=true",
            "profile.release.package.cgka-conformance-simulator.debug-assertions=true",
        ])
        profiles = campaign.build_profiles()
        self.assertFalse(profiles["default_debug_assertions"])
        self.assertEqual(profiles["legacy_control"]["executable"], "process_orchestrator")

    def test_campaign_tracks_the_registered_public_family_constants(self):
        source = (campaign.REPO / "crates/cgka-conformance-simulator/src/stateful_generator.rs").read_text()
        registered = set(re.findall(r'pub const PUBLIC_APP_\w+_FAMILY: &str = "([^"]+)";', source))
        self.assertTrue(registered)
        self.assertEqual(set(campaign.FAMILIES), registered | {"cross-route-restart-permutations/v1"})

    def plan(self, *args):
        options = campaign.parse_args(["unused", *args])
        executables = {name: name for name in (*campaign.TEST_BINARIES, "cgka-conformance-campaign")}
        inventory = {
            "app_runtime_journeys": ["public_app_01_bidirectional_messaging", "public_app_1024_message_backlog_recovers_completely"],
            "app_runtime_interaction_journeys": [
                "public_app_13_offline_removal_then_rejoin_preserves_history",
                "public_app_14_two_groups_recover_without_starving_live_traffic",
                "public_app_11_manual_self_update_advances_every_member", campaign.RACE_DIAGNOSTIC],
            "public_app_families": ["public_backlog_recovery_restart_strict_canary"],
            "process_orchestrator": [*campaign.APP_ROUTE_TESTS, "unrelated_process_test"],
            "app_generated_variance": ["seeded_recovery_schedule_survives_real_process_kills"],
        }
        return campaign.make_plan(options, executables, inventory)

    def test_full_plan_covers_every_catalog_arm_and_explicit_ignored_tests(self):
        tasks = self.plan()
        generated = [task for task in tasks if task["kind"] == "generated"]
        self.assertEqual(len(generated), 33)
        self.assertEqual(sum(task["cases"] for task in generated), 216)
        self.assertEqual({task["family"] for task in generated}, set(campaign.FAMILIES))
        tests = [task for task in tasks if task["kind"] == "test"]
        self.assertTrue(any("1024" in task["test"] for task in tests))
        self.assertTrue(any("manual_self_update" in task["test"] for task in tests))
        self.assertNotIn("unrelated_process_test", [task["test"] for task in tests])
        for task in tests:
            self.assertIn("--exact", task["command"])
            self.assertIn("--include-ignored", task["command"])
        self.assertEqual(len(tasks), len({task["id"] for task in tasks}))

    def test_canary_uses_one_seed_and_includes_all_three_additions(self):
        tasks = self.plan("--mode", "canary", "--seeds", "42", "7", "--rounds", "2")
        generated = [task for task in tasks if task["kind"] == "generated"]
        self.assertEqual(len(generated), 22)
        self.assertTrue(all(task["cases"] == 1 and task["seed"] == 42 for task in generated))
        self.assertEqual({task["test"] for task in tasks if task["kind"] == "test"}, campaign.CANARY_TESTS)
        self.assertEqual(len(tasks), len({task["id"] for task in tasks}))

    def test_cross_route_uses_an_exclusive_worker(self):
        tasks = self.plan()
        batches = campaign.execution_batches(tasks, 2)
        self.assertEqual(batches[0][1], 2)
        self.assertTrue(all(task.get("binary") != "process_orchestrator" for task in batches[0][0]))
        self.assertEqual(len(batches), 3)
        self.assertEqual(batches[1][1], 1)
        self.assertEqual(len(batches[1][0]), 1)
        self.assertEqual(batches[2][1], 1)
        self.assertEqual(batches[2][0][0]["test"], "seeded_recovery_schedule_survives_real_process_kills")
        self.assertEqual(sum(len(batch) for batch, _ in batches), len(tasks))

    def test_invalid_resource_and_seed_arguments_are_rejected(self):
        for args in (("--jobs", "3"), ("--rounds", "0"), ("--seeds", "-1"), ("--seeds", str(2**64))):
            with self.subTest(args=args), patch("sys.stderr"), self.assertRaises(SystemExit):
                campaign.parse_args(["unused", *args])

    def test_missing_partial_or_failed_summary_is_not_success(self):
        task = {"family": "public-app-send-leave/v1", "seed": 7, "cases": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(campaign.inspect_generated(task, root))
            (root / "cases").mkdir()
            path = root / "cases/process-campaign.v1.json"
            summary = {"family": task["family"], "seed": 7, "storage": "file", "cases": []}
            path.write_text(json.dumps(summary))
            self.assertTrue(campaign.inspect_generated(task, root))
            row = {"case_index": 0, "exit_code": 0, "timed_out": False, "signal": None, "artifact_integrity_errors": []}
            summary["cases"] = [row]
            path.write_text(json.dumps(summary))
            self.assertEqual(campaign.inspect_generated(task, root), [])
            for field, value in (("exit_code", 1), ("timed_out", True), ("signal", 9), ("artifact_integrity_errors", ["missing_report"])):
                summary["cases"] = [dict(row, **{field: value})]
                path.write_text(json.dumps(summary))
                self.assertTrue(campaign.inspect_generated(task, root))

    def test_zero_selected_tests_fail_even_when_libtest_exits_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = {"id": "zero", "kind": "test", "timeout": 10,
                    "command": [sys.executable, "-c", "print('test result: ok. 0 passed; 0 failed; 0 ignored;')"]}
            result = campaign.execute(task, Path(temporary), dict(os.environ))
            self.assertFalse(result["passed"])
            self.assertIn("exact test did not execute once", result["evidence_errors"])
            self.assertFalse((Path(temporary) / "zero/tmp").exists())

    def test_timeout_kills_descendants_and_preserves_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "escaped"
            child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
            parent = f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); print('started', flush=True); time.sleep(30)"
            result = campaign.run_command([sys.executable, "-c", parent], root, dict(os.environ), 0.3)
            self.assertTrue(result["timed_out"])
            self.assertIn("started", (root / "output.log").read_text())
            # Wait outside the runner to prove its descendant cannot write later.
            subprocess.run([sys.executable, "-c", "import time; time.sleep(1.1)"], check=True)
            self.assertFalse(marker.exists())

    def test_existing_evidence_root_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "source.json"
            marker.write_text("original evidence")
            with patch.object(campaign, "source_state", return_value={"status": ""}), \
                 patch.object(campaign.signal, "signal"), self.assertRaises(FileExistsError):
                campaign.main([str(root)])
            self.assertEqual(marker.read_text(), "original evidence")

    def test_failing_canary_prevents_matrix_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "new-run"
            executables = {name: sys.executable for name in (*campaign.TEST_BINARIES, "cgka-conformance-campaign")}
            names = list(campaign.CANARY_TESTS | campaign.APP_ROUTE_TESTS | {campaign.RACE_DIAGNOSTIC})
            executed = []

            def fail(task, _root, _env):
                executed.append(task)
                return dict(task, passed=False)

            with patch.object(campaign, "source_state", return_value={"status": ""}), \
                 patch.object(campaign, "git", return_value=b""), \
                 patch.object(campaign, "build", return_value=executables), \
                 patch.object(campaign, "test_names", return_value=names), \
                 patch.object(campaign, "execute", side_effect=fail), \
                 patch.object(campaign.subprocess, "check_output", return_value="rustc test"), \
                 patch.object(campaign.signal, "signal"), patch("builtins.print"):
                self.assertEqual(campaign.main([str(root)]), 1)
            self.assertTrue(executed)
            self.assertTrue(all(task["phase"] == "canary" for task in executed))
            summary = json.loads((root / "summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertLess(summary["completed"], summary["planned"])


if __name__ == "__main__":
    unittest.main()
