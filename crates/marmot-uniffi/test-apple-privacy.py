#!/usr/bin/env python3
"""Resource-loss regression tests; no Apple toolchain or Rust build required."""

import importlib.util
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("privacy", HERE / "validate-apple-privacy.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class PrivacyPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / "cargo.a"
        self.library.write_bytes(b"!<arch>\n" + b"unchanged cargo fixture")
        self.headers = self.root / "headers"
        self.headers.mkdir()
        (self.headers / "marmot_uniffiFFI.h").write_text("void example(void);\n")
        (self.headers / "module.modulemap").write_text('module marmot_uniffiFFI { header "marmot_uniffiFFI.h" export * }\n')

    def artifact(self, platform, analytics=False):
        xc = self.root / f"{platform}.xcframework"
        framework = xc / "arm64/marmot_uniffiFFI.framework"
        privacy.framework.stage(self.library, self.headers, framework, platform, "18.0",
                                analytics, HERE / "apple-privacy")
        (xc / "Info.plist").write_bytes(plistlib.dumps(dict(AvailableLibraries=[dict(
            LibraryIdentifier="arm64", LibraryPath=framework.name, SupportedPlatform=platform)])))
        manifest = framework / ("Resources" if platform == "macos" else "") / "PrivacyInfo.xcprivacy"
        return xc, framework, manifest

    def test_platform_layout_and_unchanged_binary(self):
        for platform in ("ios", "macos"):
            xc, framework, manifest = self.artifact(platform)
            privacy.check_xcframework(xc)
            self.assertEqual(self.library.read_bytes(), (framework / "marmot_uniffiFFI").read_bytes())
            manifest.unlink()
            with self.assertRaises(FileNotFoundError):
                privacy.check_xcframework(xc)

    def test_analytics_is_feature_selected(self):
        xc, _, manifest = self.artifact("ios", True)
        privacy.check_xcframework(xc)
        rows = plistlib.loads(manifest.read_bytes())["NSPrivacyCollectedDataTypes"]
        self.assertTrue(any(r["NSPrivacyCollectedDataType"].endswith("CoarseLocation") for r in rows))
        self.assertFalse(any(r["NSPrivacyCollectedDataType"].endswith("CoarseLocation")
                             for r in privacy.framework.privacy_manifest()["NSPrivacyCollectedDataTypes"]))

    def test_invalid_purpose_and_boolean_fail(self):
        _, _, manifest = self.artifact("ios")
        for key, value in [("NSPrivacyCollectedDataTypePurposes", ["Analytics"]),
                           ("NSPrivacyCollectedDataTypeLinked", 1)]:
            data = privacy.framework.privacy_manifest()
            data["NSPrivacyCollectedDataTypes"][0][key] = value
            manifest.write_bytes(plistlib.dumps(data))
            with self.assertRaises(ValueError):
                privacy.check_manifest(manifest)

    def test_slice_feature_mismatch_fails(self):
        xc, _, _ = self.artifact("ios")
        shutil.copytree(xc / "arm64", xc / "simulator")
        info = plistlib.loads((xc / "Info.plist").read_bytes())
        second = dict(info["AvailableLibraries"][0], LibraryIdentifier="simulator")
        info["AvailableLibraries"].append(second)
        (xc / "Info.plist").write_bytes(plistlib.dumps(info))
        manifest = xc / "simulator/marmot_uniffiFFI.framework/PrivacyInfo.xcprivacy"
        manifest.write_bytes(plistlib.dumps(privacy.framework.privacy_manifest(True)))
        with self.assertRaises(ValueError):
            privacy.check_xcframework(xc)

    def test_packaged_source_is_validation_baseline(self):
        xc, _, manifest = self.artifact("ios")
        source = self.root / "packaged-source-privacy"
        shutil.copytree(HERE / "apple-privacy", source)
        data = plistlib.loads(manifest.read_bytes())
        data["NSPrivacyCollectedDataTypes"].reverse()
        (source / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(data))
        manifest.write_bytes(plistlib.dumps(data))
        with self.assertRaises(ValueError):
            privacy.check_xcframework(xc)
        privacy.check_xcframework(xc, source, False)
        with self.assertRaises(ValueError):
            privacy.check_xcframework(xc, source, True)

    def test_zip_preserves_versioned_framework(self):
        xc, _, _ = self.artifact("macos")
        archive = self.root / "release.zip"
        subprocess.run(["zip", "-qry", str(archive), xc.name], cwd=self.root, check=True)
        extracted = self.root / "extracted"
        subprocess.run(["unzip", "-q", str(archive), "-d", str(extracted)], check=True)
        unpacked = extracted / xc.name
        privacy.check_xcframework(unpacked)
        current = unpacked / "arm64/marmot_uniffiFFI.framework/Versions/Current"
        self.assertTrue(current.is_symlink())
        current.unlink()
        shutil.copytree(current.parent / "A", current)
        with self.assertRaises(ValueError):
            privacy.check_xcframework(unpacked)

    def test_input_resource_does_not_count_as_archived(self):
        xc, _, manifest = self.artifact("ios")
        archive = self.root / "Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        app.mkdir(parents=True)
        # Even an identical host manifest does not prove SDK resource delivery.
        (app / "PrivacyInfo.xcprivacy").write_bytes(manifest.read_bytes())
        with self.assertRaises(ValueError):
            privacy.check_archive(archive, xc)
        resource = app / "Frameworks/marmot_uniffiFFI.framework/PrivacyInfo.xcprivacy"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(manifest.read_bytes())
        privacy.check_archive(archive, xc, analytics=False)
        with self.assertRaises(ValueError):
            privacy.check_archive(archive, xc, analytics=True)
        embedded_binary = resource.parent / "marmot_uniffiFFI"
        embedded_binary.write_bytes(self.library.read_bytes())
        with self.assertRaises(ValueError):
            privacy.check_archive(archive, xc, analytics=False)
        with self.assertRaises(ValueError):
            privacy.check_archive(archive, xc, analytics=True)
        embedded_binary.unlink()
        resource.unlink()
        with self.assertRaises(ValueError):
            privacy.check_archive(archive, xc)


if __name__ == "__main__":
    unittest.main()
