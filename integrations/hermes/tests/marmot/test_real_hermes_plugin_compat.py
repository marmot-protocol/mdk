import importlib
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
            for name in PROBE.PLUGIN_ONLY_RUNTIME_FILES:
                self.assertTrue((artifact / name).is_file(), name)
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

    def test_plugin_only_artifact_imports_doctor_without_adapter(self):
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
            pkg_root = Path(temp) / "pkg"
            pkg_root.mkdir()
            (pkg_root / "marmot").symlink_to(artifact)
            sys.path.insert(0, str(pkg_root))
            try:
                for name in ("marmot.doctor", "marmot.diagnostics"):
                    sys.modules.pop(name, None)
                sys.modules.pop("marmot", None)
                doctor = importlib.import_module("marmot.doctor")
                self.assertTrue(callable(doctor.collect))
                self.assertTrue(callable(doctor.main))
                self.assertNotIn("marmot.adapter", sys.modules)
            finally:
                if sys.path and sys.path[0] == str(pkg_root):
                    sys.path.pop(0)
                for name in ("marmot.doctor", "marmot.diagnostics", "marmot"):
                    sys.modules.pop(name, None)

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

    def test_plugin_test_tempdir_ignores_cleanup_errors(self):
        temp = PROBE._plugin_test_tempdir()
        try:
            self.assertTrue(temp._ignore_cleanup_errors)
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
