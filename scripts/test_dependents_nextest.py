#!/usr/bin/env python3
"""Unit tests for `scripts/dependents_nextest.py`, the land-change dependent-suite selection."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dependents_nextest import TEST_FILTER, nextest_command  # noqa: E402

FEATURES = ["wn-cli/test-policy-overrides", "cgka-engine/test-policy-overrides", "cgka-engine/test-crash-hooks"]


def metadata(packages: dict[str, tuple[str, list[str]]]) -> dict:
    """Build minimal `cargo metadata` output: name -> (directory, workspace dependencies)."""
    root = "/ws"
    return {
        "workspace_root": root,
        "workspace_members": [f"{name}-id" for name in packages],
        "packages": [
            {"id": f"{name}-id", "name": name, "manifest_path": f"{root}/{d}/Cargo.toml"}
            for name, (d, _) in packages.items()
        ],
        "resolve": {
            "nodes": [
                {"id": f"{name}-id", "deps": [{"pkg": f"{dep}-id"} for dep in deps]}
                for name, (_, deps) in packages.items()
            ]
        },
    }


# A slice of the real graph. The regressions that broke master on 2026-11-26/27 all failed
# in `marmot-session` or `marmot-app` suites that the authors' local checks never ran.
WORKSPACE = metadata(
    {
        "cgka-engine": ("crates/cgka-engine", []),
        "transport-nostr": ("crates/transport-nostr", []),
        "marmot-session": ("crates/marmot-session", ["cgka-engine"]),
        "marmot-app": ("crates/marmot-app", ["marmot-session", "transport-nostr"]),
        "wn-cli": ("crates/cli", ["marmot-app"]),
        "cgka-conformance-simulator": ("crates/cgka-conformance-simulator", ["marmot-app"]),
        "marmot-markdown": ("crates/marmot-markdown", []),
        "marmot-markdown-ast": ("crates/marmot-markdown/ast", []),
    }
)


def packages(command: list[str]) -> list[str]:
    return [command[i + 1] for i, arg in enumerate(command) if arg == "-p"]


def features(command: list[str]) -> list[str]:
    return command[command.index("--features") + 1].split(",") if "--features" in command else []


class DependentsNextestTests(unittest.TestCase):
    def test_a_lower_crate_change_runs_every_crate_that_depends_on_it(self):
        # #3814 changed `transport-nostr` and broke `marmot-app` tests; local checks ran
        # only `transport-nostr`.
        command = nextest_command(["crates/transport-nostr/src/lib.rs"], WORKSPACE, FEATURES)
        self.assertEqual(packages(command), ["marmot-app", "transport-nostr", "wn-cli"])
        self.assertEqual(command[-2:], ["-E", TEST_FILTER])

    def test_canary_features_are_kept_only_where_cargo_accepts_them(self):
        # Cargo rejects `pkg/feature` unless `pkg` is selected or a direct dependency of one.
        session = nextest_command(["crates/marmot-session/src/runtime.rs"], WORKSPACE, FEATURES)
        self.assertEqual(packages(session), ["marmot-app", "marmot-session", "wn-cli"])
        self.assertEqual(features(session), FEATURES)
        nostr = nextest_command(["crates/transport-nostr/src/lib.rs"], WORKSPACE, FEATURES)
        self.assertEqual(features(nostr), ["wn-cli/test-policy-overrides"])
        markdown = nextest_command(["crates/marmot-markdown/src/lib.rs"], WORKSPACE, FEATURES)
        self.assertNotIn("--features", markdown)

    def test_a_nested_crate_change_belongs_to_the_innermost_crate(self):
        command = nextest_command(["crates/marmot-markdown/ast/src/lib.rs"], WORKSPACE, FEATURES)
        self.assertEqual(packages(command), ["marmot-markdown-ast"])

    def test_shared_build_inputs_select_the_whole_workspace_except_the_simulator(self):
        for shared in ("Cargo.lock", "Cargo.toml", ".cargo/config.toml", "rust-toolchain.toml", ".config/nextest.toml"):
            with self.subTest(shared=shared):
                command = nextest_command([shared], WORKSPACE, FEATURES)
                self.assertNotIn("cgka-conformance-simulator", packages(command))
                self.assertEqual(len(packages(command)), 7)

    def test_docs_and_non_crate_changes_select_nothing(self):
        for files in (["crates/marmot-app/AGENTS.md"], ["scripts/dependents_nextest.py"], ["docs/x.md"]):
            with self.subTest(files=files):
                self.assertIsNone(nextest_command(files, WORKSPACE, FEATURES))

    def test_a_simulator_only_change_is_left_to_its_own_smoke(self):
        self.assertIsNone(nextest_command(["crates/cgka-conformance-simulator/src/lib.rs"], WORKSPACE, FEATURES))


if __name__ == "__main__":
    unittest.main()
