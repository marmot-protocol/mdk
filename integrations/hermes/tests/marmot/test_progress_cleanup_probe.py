import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[4]
PROBE_DIR = Path(__file__).resolve().parent
if str(PROBE_DIR) not in sys.path:
    sys.path.insert(0, str(PROBE_DIR))

import progress_cleanup_probe as probe  # noqa: E402


class TestProgressCleanupProbeFailClosed(unittest.TestCase):
    def test_registered_hermes_home_requires_installed_plugin(self):
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}, clear=False):
                with self.assertRaisesRegex(AssertionError, "installed Marmot plugin"):
                    probe._registered_hermes_home()
            plugin = home / "plugins" / "marmot"
            plugin.mkdir(parents=True)
            (plugin / "adapter.py").write_text("# fixture\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}, clear=False):
                self.assertEqual(probe._registered_hermes_home(), home)

    def test_missing_delete_registry_entry_fails_without_private_fallback(self):
        fake_registry = types.SimpleNamespace(get_entry=lambda _name: None)
        fake_module = types.ModuleType("tools.registry")
        fake_module.registry = fake_registry
        with mock.patch.dict(sys.modules, {"tools": types.ModuleType("tools"), "tools.registry": fake_module}):
            with self.assertRaisesRegex(AssertionError, "was not registered"):
                probe._registered_delete_handler()
            probe._assert_missing_delete_registration_fails()

    def test_missing_platform_factory_fails_without_private_fallback(self):
        fake_registry = types.SimpleNamespace(create_adapter=lambda *_args, **_kwargs: None)
        fake_module = types.ModuleType("gateway.platform_registry")
        fake_module.platform_registry = fake_registry
        with mock.patch.dict(
            sys.modules,
            {
                "gateway": types.ModuleType("gateway"),
                "gateway.platform_registry": fake_module,
            },
        ):
            with self.assertRaisesRegex(AssertionError, "returned no adapter"):
                probe._create_registered_adapter(object())
            probe._assert_missing_factory_fails()

    def test_fresh_progress_state_fails_closed_when_attribute_missing(self):
        with self.assertRaisesRegex(AssertionError, "missing _tool_progress_events"):
            probe._assert_fresh_progress_state(object())
        with self.assertRaisesRegex(AssertionError, "reconstructed"):
            probe._assert_fresh_progress_state(types.SimpleNamespace(_tool_progress_events=None))
        with self.assertRaisesRegex(AssertionError, "reconstructed"):
            probe._assert_fresh_progress_state(
                types.SimpleNamespace(_tool_progress_events={"keep": {"synthetic"}})
            )
        probe._assert_fresh_progress_state(types.SimpleNamespace(_tool_progress_events={}))

    def test_home_env_restored_after_success_and_exception(self):
        original_home = os.environ.get("HOME")
        original_hermes = os.environ.get("HERMES_HOME")
        os.environ["HOME"] = "/tmp/progress-cleanup-home-original"
        os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-original"
        try:
            with probe._preserve_home_env():
                os.environ["HOME"] = "/tmp/progress-cleanup-home-mutated"
                os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-mutated"
            self.assertEqual(os.environ["HOME"], "/tmp/progress-cleanup-home-original")
            self.assertEqual(os.environ["HERMES_HOME"], "/tmp/progress-cleanup-hermes-original")
            with self.assertRaises(RuntimeError):
                with probe._preserve_home_env():
                    os.environ["HOME"] = "/tmp/progress-cleanup-home-failed"
                    os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-failed"
                    raise RuntimeError("fixture failed")
            self.assertEqual(os.environ["HOME"], "/tmp/progress-cleanup-home-original")
            self.assertEqual(os.environ["HERMES_HOME"], "/tmp/progress-cleanup-hermes-original")
        finally:
            probe._restore_home_env(original_home, original_hermes)

    def test_seed_preserves_existing_plugin_entries(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        spec_name = "hermes_marmot_configure_gateway"
        if spec_name in sys.modules:
            helper = sys.modules[spec_name]
        else:
            helper = probe._load_helper()
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            home.mkdir(parents=True, exist_ok=True)
            (home / "config.yaml").write_text(
                "\n".join(
                    [
                        "plugins:",
                        "  entries:",
                        "    marmot:",
                        "      enabled: true",
                        "      settings:",
                        "        keep: retained",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            probe._write_seed_with_global_cleanup(home, helper)
            config = helper.load_config(home / "config.yaml")
            self.assertTrue(config["plugins"]["entries"]["marmot"]["enabled"])
            self.assertEqual(config["plugins"]["entries"]["marmot"]["settings"]["keep"], "retained")
            self.assertIs(config["display"]["cleanup_progress"], True)
            self.assertIs(config["display"]["platforms"]["marmot"]["cleanup_progress"], False)


if __name__ == "__main__":
    unittest.main()
