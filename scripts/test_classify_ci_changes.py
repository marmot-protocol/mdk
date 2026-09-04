#!/usr/bin/env python3
"""Regression tests for conservative CI path classification."""

from __future__ import annotations

import unittest

from classify_ci_changes import classify


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
        self.assertFalse(result["run_c"])

    def test_ci_workflow_change_runs_every_lane(self) -> None:
        result = classify([".github/workflows/ci.yml"])
        self.assertTrue(all(result.values()))

    def test_empty_or_manual_classification_fails_open_to_full_ci(self) -> None:
        self.assertTrue(all(classify([]).values()))
        self.assertTrue(all(classify(["README.md"], force_all=True).values()))


if __name__ == "__main__":
    unittest.main()
