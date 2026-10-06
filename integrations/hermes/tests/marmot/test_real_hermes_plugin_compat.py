import importlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPT_PATH = Path(__file__).with_name("test_real_hermes_plugin.py")
SPEC = importlib.util.spec_from_file_location("marmot_real_hermes_probe", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class SourceInstallCapabilityTests(unittest.TestCase):
    def test_local_fixture_scan_confirmation_is_explicit(self):
        with mock.patch.object(sys, "argv", [str(SCRIPT_PATH)]):
            self.assertFalse(PROBE._parse_args().accept_known_local_plugin_caution)
        with mock.patch.object(sys, "argv", [str(SCRIPT_PATH), "--accept-known-local-plugin-caution"]):
            self.assertTrue(PROBE._parse_args().accept_known_local_plugin_caution)

    def test_scan_preflight_only_confirms_observed_caution(self):
        class Blocked(Exception):
            def __init__(self, result):
                self.scan_result = result

        for verdict, consent, expected in (
            ("safe", False, False), ("safe", True, False),
            ("caution", False, None), ("caution", True, True),
            ("dangerous", False, None), ("dangerous", True, None),
        ):
            with self.subTest(verdict=verdict, consent=consent):
                guard = types.ModuleType("tools.plugin_guard")
                guard.scan_plugin = lambda *a, **kw: types.SimpleNamespace(
                    verdict=verdict, findings=[types.SimpleNamespace(pattern_id="python_subprocess")])
                def scan(*a, force, **kw):
                    result = guard.scan_plugin()
                    if result.verdict == "dangerous" or result.verdict == "caution" and not force:
                        raise Blocked(result)
                    return result
                command = types.SimpleNamespace(_scan_plugin_tree=scan, PluginScanBlocked=Blocked)
                with mock.patch.dict(sys.modules, {"tools.plugin_guard": guard}):
                    if expected is None:
                        with self.assertRaises(Blocked):
                            PROBE._local_plugin_install_force(command, Path("fixture"), accept_caution=consent)
                    else:
                        self.assertIs(PROBE._local_plugin_install_force(
                            command, Path("fixture"), accept_caution=consent), expected)

    def test_scan_preflight_rejects_unknown_or_empty_caution_findings(self):
        class Blocked(Exception):
            def __init__(self, result):
                self.scan_result = result
        for patterns in ([], ["new_scanner_pattern"], ["python_subprocess", "new_scanner_pattern"]):
            with self.subTest(patterns=patterns):
                result = types.SimpleNamespace(verdict="caution", findings=[
                    types.SimpleNamespace(pattern_id=pattern) for pattern in patterns])
                scan = mock.Mock(side_effect=Blocked(result))
                command = types.SimpleNamespace(_scan_plugin_tree=scan, PluginScanBlocked=Blocked)
                with self.assertRaises(Blocked):
                    PROBE._local_plugin_install_force(command, Path("fixture"), accept_caution=True)
                scan.assert_called_once_with(Path("fixture"), "pinned-local-fixture", force=False)

    def test_scan_preflight_rejects_a_host_that_forces_dangerous_verdicts(self):
        class Blocked(Exception):
            def __init__(self, result):
                self.scan_result = result
        guard = types.ModuleType("tools.plugin_guard")
        guard.scan_plugin = lambda *a, **kw: types.SimpleNamespace(verdict="caution", findings=[types.SimpleNamespace(pattern_id="python_subprocess")])
        def scan(*a, force, **kw):
            result = guard.scan_plugin()
            if not force:
                raise Blocked(result)
            return result
        command = types.SimpleNamespace(_scan_plugin_tree=scan, PluginScanBlocked=Blocked)
        with mock.patch.dict(sys.modules, {"tools.plugin_guard": guard}):
            with self.assertRaisesRegex(AssertionError, "allows a dangerous"):
                PROBE._local_plugin_install_force(command, Path("fixture"), accept_caution=True)

    def test_older_hosts_without_scanner_never_force_install(self):
        self.assertFalse(PROBE._local_plugin_install_force(
            types.SimpleNamespace(), Path("fixture"), accept_caution=True))

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
            subprocess.run(
                [
                    sys.executable, "-B", "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); "
                    "from marmot import doctor; "
                    "assert callable(doctor.collect); assert callable(doctor.main); "
                    "assert 'marmot.adapter' not in sys.modules",
                    str(pkg_root),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

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
