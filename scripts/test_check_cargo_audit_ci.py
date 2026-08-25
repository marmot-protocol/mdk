#!/usr/bin/env python3
"""Regression tests for the cargo-audit workflow policy check."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_cargo_audit_ci import PolicyError, validate


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
AUDIT_CONFIG = REPO_ROOT / ".cargo" / "audit.toml"


class CargoAuditCiPolicyTests(unittest.TestCase):
    def test_repository_workflow_enforces_audit_policy(self) -> None:
        validate(WORKFLOW, AUDIT_CONFIG)

    def assert_mutation_rejected(self, old: str, new: str, message: str) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(old, workflow)
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "ci.yml"
            mutated.write_text(workflow.replace(old, new, 1), encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, message):
                validate(mutated, AUDIT_CONFIG)

    def assert_workflow_rejected(self, workflow: str, message: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "ci.yml"
            mutated.write_text(workflow, encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, message):
                validate(mutated, AUDIT_CONFIG)

    def assert_audit_config_mutation_rejected(
        self, old: str, new: str, message: str
    ) -> None:
        audit_config = AUDIT_CONFIG.read_text(encoding="utf-8")
        self.assertIn(old, audit_config)
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "audit.toml"
            mutated.write_text(audit_config.replace(old, new, 1), encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, message):
                validate(WORKFLOW, mutated)

    def test_rejects_missing_rust_toolchain_setup(self) -> None:
        self.assert_mutation_rejected(
            '          rustup toolchain install "$toolchain" --profile minimal\n',
            "",
            "repository Rust toolchain",
        )

    def test_rejects_changed_cargo_audit_pin(self) -> None:
        self.assert_mutation_rejected(
            "tool: cargo-audit@0.22.1",
            "tool: cargo-audit@latest",
            "cargo-audit@0.22.1",
        )

    def test_rejects_unlocked_or_bypassed_audit_command(self) -> None:
        self.assert_mutation_rejected(
            "run: cargo --locked audit",
            "run: cargo audit || true",
            "exactly 'cargo --locked audit'",
        )

    def test_rejects_removed_audit_job(self) -> None:
        self.assert_mutation_rejected(
            "  rust-audit:",
            "  rust-audit-disabled:",
            "rust-audit job",
        )

    def test_rejects_error_masking(self) -> None:
        self.assert_mutation_rejected(
            "  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n\n    steps:",
            "  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    continue-on-error: true\n\n    steps:",
            "continue-on-error",
        )

    def test_rejects_job_level_condition(self) -> None:
        self.assert_mutation_rejected(
            "  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n\n    steps:",
            "  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    if: ${{ false }}\n\n    steps:",
            "must not have an if condition",
        )

    def test_rejects_step_level_condition(self) -> None:
        self.assert_mutation_rejected(
            "      - name: Audit Rust dependencies\n",
            "      - name: Audit Rust dependencies\n        if: ${{ false }}\n",
            "must not have an if condition",
        )

    def test_rejects_quoted_condition_key(self) -> None:
        self.assert_mutation_rejected(
            "  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n",
            '  rust-audit:\n    name: Rust audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    "if": ${{ false }}\n',
            "must not have an if condition",
        )

    def test_commented_next_job_boundary_does_not_supply_audit_command(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        workflow = workflow.replace(
            "  terminal-harness-installers:\n",
            "  terminal-harness-installers: # annotated boundary\n",
            1,
        ).replace("run: cargo --locked audit", "run: echo audit-disabled", 1)
        marker = "      - name: Test Codex, Pi, and OpenCode installers\n"
        self.assertIn(marker, workflow)
        workflow = workflow.replace(
            marker,
            "      - name: Synthetic unrelated audit command\n"
            "        run: cargo --locked audit\n\n"
            + marker,
            1,
        )
        self.assert_workflow_rejected(workflow, "exactly 'cargo --locked audit'")

    def test_rejects_non_root_working_directory(self) -> None:
        self.assert_mutation_rejected(
            "      - name: Audit Rust dependencies\n",
            "      - name: Audit Rust dependencies\n        working-directory: crates/cli\n",
            "repository root",
        )

    def test_rejects_missing_audit_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "audit.toml"
            with self.assertRaisesRegex(PolicyError, "audit.toml"):
                validate(WORKFLOW, missing)

    def test_rejects_changed_missing_or_invalid_advisory_policy(self) -> None:
        approved = 'ignore = ["RUSTSEC-2024-0384"]'
        mutations = (
            'ignore = ["RUSTSEC-2024-0384", "RUSTSEC-2099-0001"]',
            'ignore = ["RUSTSEC-2099-0001"]',
            'ignore = []',
            'ignore = [',
            'ignore = ["RUSTSEC-2024-0384"]\nseverity_threshold = "critical"',
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_audit_config_mutation_rejected(
                    approved,
                    mutation,
                    "audit.toml|exactly match the approved policy",
                )


if __name__ == "__main__":
    unittest.main()
