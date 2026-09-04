#!/usr/bin/env python3
"""Regression tests for conservative CI path classification."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

from classify_ci_changes import classify


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LITERAL_INCLUDE = re.compile(
    r'\binclude_(?:str|bytes)!\s*\(\s*"([^"\r\n]+)"\s*\)', re.MULTILINE
)


class ClassifyCiChangesTests(unittest.TestCase):
    def test_documentation_only_change_uses_short_lane(self) -> None:
        self.assertEqual(
            classify(["README.md", "docs/marmot-architecture/index.md"]),
            {
                "run_full": False,
                "run_c": False,
                "run_conformance": False,
                "run_ios": False,
                "run_formal": False,
            },
        )

    def test_unknown_non_documentation_change_fails_open_to_every_lane(self) -> None:
        result = classify(["integrations/codex/marmot/src/main.rs"])
        self.assertTrue(all(result.values()))

    def test_known_independent_crate_keeps_specialist_jobs_filtered(self) -> None:
        result = classify(["crates/cli/src/main.rs"])
        self.assertTrue(result["run_full"])
        self.assertFalse(result["run_c"])
        self.assertFalse(result["run_conformance"])
        self.assertFalse(result["run_ios"])
        self.assertFalse(result["run_formal"])

    def test_new_workspace_crate_fails_open_until_classified(self) -> None:
        result = classify(["crates/new-workspace-member/src/lib.rs"])
        self.assertTrue(all(result.values()))

    def test_engine_change_runs_all_compiled_specialists_except_formal_model(self) -> None:
        result = classify(["crates/cgka-engine/src/lib.rs"])
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_c"])
        self.assertTrue(result["run_conformance"])
        self.assertTrue(result["run_ios"])
        self.assertFalse(result["run_formal"])

    def test_executable_markdown_runs_its_simulator_gate(self) -> None:
        result = classify(
            ["crates/cgka-conformance-simulator/PROTOCOL_DECISIONS.md"]
        )
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_conformance"])

    def test_markdown_golden_fixture_runs_compiled_consumers(self) -> None:
        result = classify(["crates/marmot-markdown/tests/golden/kitchen_sink.md"])
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_c"])
        self.assertTrue(result["run_conformance"])

    def test_non_markdown_assurance_inventory_is_not_treated_as_docs(self) -> None:
        result = classify(
            ["docs/marmot-architecture/convergence-constant-inventory.txt"]
        )
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_conformance"])

    def test_formal_model_change_runs_proofs(self) -> None:
        result = classify(["formal/tamarin/convergence.spthy"])
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_formal"])
        self.assertTrue(result["run_conformance"])
        self.assertFalse(result["run_c"])

    def test_shared_tamarin_policy_input_runs_formal_and_conformance(self) -> None:
        result = classify(["formal/tamarin/policy_cases.json"])
        self.assertTrue(result["run_full"])
        self.assertTrue(result["run_formal"])
        self.assertTrue(result["run_conformance"])

    def test_tla_liveness_inputs_run_only_the_conformance_specialist(self) -> None:
        for path in [
            "formal/liveness/ConvergenceLifecycle.tla",
            "formal/liveness/ConvergenceLifecycle.fair.cfg",
            "formal/liveness/counterexamples/admin-starvation.scenario.json",
        ]:
            with self.subTest(path=path):
                result = classify([path])
                self.assertTrue(result["run_full"])
                self.assertTrue(result["run_conformance"])
                self.assertFalse(result["run_c"])
                self.assertFalse(result["run_ios"])
                self.assertFalse(result["run_formal"])

    def test_literal_rust_includes_preserve_their_consumers_lanes(self) -> None:
        tracked_rust = subprocess.run(
            ["git", "ls-files", "-z", "--", "*.rs"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        failures = []

        for encoded_source in tracked_rust:
            if not encoded_source:
                continue
            source = REPOSITORY_ROOT / encoded_source.decode("utf-8")
            source_path = source.relative_to(REPOSITORY_ROOT).as_posix()
            source_lanes = {
                lane for lane, selected in classify([source_path]).items() if selected
            }
            source_text = source.read_text(encoding="utf-8")

            for included_path in LITERAL_INCLUDE.findall(source_text):
                included = (source.parent / included_path).resolve()
                if not included.is_file():
                    continue
                try:
                    included_path = included.relative_to(REPOSITORY_ROOT).as_posix()
                except ValueError:
                    continue
                included_lanes = {
                    lane
                    for lane, selected in classify([included_path]).items()
                    if selected
                }
                missing_lanes = sorted(source_lanes - included_lanes)
                if missing_lanes:
                    failures.append(
                        f"{included_path}, included by {source_path}, misses "
                        f"{', '.join(missing_lanes)}"
                    )

        self.assertFalse(
            failures,
            "literal Rust includes must select every lane used by their consumers:\n"
            + "\n".join(failures),
        )

    def test_ci_workflow_change_runs_every_lane(self) -> None:
        result = classify([".github/workflows/ci.yml"])
        self.assertTrue(all(result.values()))

    def test_empty_or_manual_classification_fails_open_to_full_ci(self) -> None:
        self.assertTrue(all(classify([]).values()))
        self.assertTrue(all(classify(["README.md"], force_all=True).values()))


if __name__ == "__main__":
    unittest.main()
