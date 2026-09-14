import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).with_name("test_real_hermes_plugin.py")
SPEC = importlib.util.spec_from_file_location("marmot_real_hermes_probe", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class SourceInstallCapabilityTests(unittest.TestCase):
    def test_plugin_only_artifact_contains_and_imports_inbound_spool(self):
        mdk_source = Path(__file__).resolve().parents[4]
        mdk_ref = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=mdk_source,
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as temp:
            artifact = PROBE._plugin_only_repository(
                mdk_source,
                mdk_ref,
                Path(temp),
            )
            spool_path = artifact / "inbound_spool.py"
            spec = importlib.util.spec_from_file_location(
                "installed_marmot_inbound_spool",
                spool_path,
            )
            if spec is None or spec.loader is None:
                self.fail("could not load installed inbound spool artifact")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            self.assertTrue(callable(module.InboundSpool))

    def test_ref_parameter_does_not_imply_subdirectory_support(self):
        class RefOnlyPluginsCommand:
            @staticmethod
            def _resolve_git_url(identifier):
                return identifier

        self.assertFalse(
            PROBE._source_install_supports_subdirectories(RefOnlyPluginsCommand)
        )

    def test_fragment_splitting_proves_subdirectory_support(self):
        class SubdirectoryPluginsCommand:
            @staticmethod
            def _resolve_git_url(identifier):
                repository, _, subdir = identifier.partition("#")
                return repository, subdir

        self.assertTrue(
            PROBE._source_install_supports_subdirectories(SubdirectoryPluginsCommand)
        )


if __name__ == "__main__":
    unittest.main()
