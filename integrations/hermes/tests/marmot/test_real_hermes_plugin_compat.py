import importlib.util
from pathlib import Path
import unittest


SCRIPT_PATH = Path(__file__).with_name("test_real_hermes_plugin.py")
SPEC = importlib.util.spec_from_file_location("marmot_real_hermes_probe", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class SourceInstallCapabilityTests(unittest.TestCase):
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
