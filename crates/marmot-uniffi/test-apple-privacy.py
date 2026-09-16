#!/usr/bin/env python3
"""Privacy delivery and distribution regressions; no Apple toolchain required."""

import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("privacy", HERE / "validate-apple-privacy.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class PrivacyPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, platform="ios", analytics=False):
        package = self.root / "inputs"
        package.mkdir()
        resource = package / "PrivacyInfo.xcprivacy"
        resource.write_bytes(plistlib.dumps(privacy.framework.privacy_manifest(analytics)))
        xc = package / "MarmotKit.xcframework"
        entries = []
        for variant in (["", "simulator"] if platform == "ios" else [""]):
            identifier = platform + "-arm64" + ("-" + variant if variant else "")
            slice_dir = xc / identifier
            (slice_dir / "Headers").mkdir(parents=True)
            (slice_dir / "libmarmot_uniffi.a").write_bytes(b"!<arch>\nunchanged archive fixture")
            (slice_dir / "Headers/marmot_uniffiFFI.h").write_text("void fixture(void);\n")
            (slice_dir / "Headers/module.modulemap").write_text('module marmot_uniffiFFI { header "marmot_uniffiFFI.h" }\n')
            entry = dict(LibraryIdentifier=identifier, LibraryPath="libmarmot_uniffi.a", HeadersPath="Headers",
                         SupportedPlatform=platform, SupportedArchitectures=["arm64"])
            if variant:
                entry["SupportedPlatformVariant"] = variant
            entries.append(entry)
        (xc / "Info.plist").write_bytes(plistlib.dumps(dict(AvailableLibraries=entries)))
        return package

    def test_feature_selected_reviewed_privacy(self):
        for analytics in (False, True):
            package = self.fixture(analytics=analytics)
            privacy.check_manifest(package / "PrivacyInfo.xcprivacy", analytics=analytics)
            with self.assertRaises(ValueError):
                privacy.check_manifest(package / "PrivacyInfo.xcprivacy", analytics=not analytics)
            shutil.rmtree(package)

    def test_packaged_source_not_builder_is_baseline(self):
        package = self.fixture()
        source = self.root / "source-privacy"
        shutil.copytree(HERE / "apple-privacy", source)
        data = privacy.framework.privacy_manifest()
        data["NSPrivacyCollectedDataTypes"].reverse()
        (source / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(data))
        (package / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(data))
        with self.assertRaises(ValueError):
            privacy.check_manifest(package / "PrivacyInfo.xcprivacy")
        privacy.check_manifest(package / "PrivacyInfo.xcprivacy", source, False)

    def test_invalid_privacy_values(self):
        package = self.fixture()
        for key, value in [("NSPrivacyCollectedDataTypePurposes", ["Analytics"]),
                           ("NSPrivacyCollectedDataTypeLinked", 1)]:
            data = privacy.framework.privacy_manifest()
            data["NSPrivacyCollectedDataTypes"][0][key] = value
            (package / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(data))
            with self.assertRaises(ValueError):
                privacy.check_manifest(package / "PrivacyInfo.xcprivacy")

    def test_release_inputs_must_match_hashes_and_features(self):
        package = self.fixture()
        binding = package / "MarmotKit-test.swift"
        binding.write_text("// matching binding")
        artifact = package / "MarmotKitFFI-test.xcframework.zip"
        artifact.write_bytes(b"fixture zip")
        resource = package / "PrivacyInfo.xcprivacy"
        metadata = dict(distribution="static-library-and-privacy-v1", name="marmotkit-ios", features=[],
                        artifacts={p.name: {"sha256": privacy.digest(p)} for p in (artifact, binding, resource)})
        manifest = package / "manifest.json"
        manifest.write_text(json.dumps(metadata))
        privacy.check_release(manifest, artifact, binding, resource, "ios", HERE / "apple-privacy", False)
        for path in (artifact, binding, resource):
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                privacy.check_release(manifest, artifact, binding, resource, "ios", HERE / "apple-privacy", False)
            path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "features"):
            privacy.check_release(manifest, artifact, binding, resource, "ios", HERE / "apple-privacy", True)
        with self.assertRaisesRegex(ValueError, "platform"):
            privacy.check_release(manifest, artifact, binding, resource, "macos", HERE / "apple-privacy", False)

    def test_required_slices_and_resource_free_layout(self):
        for platform in ("ios", "macos"):
            package = self.fixture(platform)
            xc = package / "MarmotKit.xcframework"
            privacy.check_xcframework(xc)
            path = xc / "Info.plist"
            info = plistlib.loads(path.read_bytes())
            original = path.read_bytes()
            info["AvailableLibraries"].pop()
            path.write_bytes(plistlib.dumps(info))
            with self.assertRaisesRegex(ValueError, "platform slices"):
                privacy.check_xcframework(xc)
            path.write_bytes(original)
            (xc / "marmot_uniffiFFI.framework").mkdir()
            with self.assertRaisesRegex(ValueError, "framework resources"):
                privacy.check_xcframework(xc)
            shutil.rmtree(package)

    def test_slice_contract_rejects_frameworks_and_invalid_metadata(self):
        for field, value, message in [
            ("LibraryPath", "marmot_uniffiFFI.framework", "raw static-library"),
            ("HeadersPath", "marmot_uniffiFFI.framework/Headers", "raw static-library"),
            ("LibraryIdentifier", "../outside", "slice identifier"),
            ("SupportedArchitectures", ["x86_64"], "architecture/platform"),
        ]:
            with self.subTest(field=field):
                package = self.fixture()
                path = package / "MarmotKit.xcframework/Info.plist"
                info = plistlib.loads(path.read_bytes())
                info["AvailableLibraries"][0][field] = value
                path.write_bytes(plistlib.dumps(info))
                with self.assertRaisesRegex(ValueError, message):
                    privacy.check_xcframework(package / "MarmotKit.xcframework")
                shutil.rmtree(package)

    def test_duplicate_platform_is_rejected(self):
        package = self.fixture()
        path = package / "MarmotKit.xcframework/Info.plist"
        info = plistlib.loads(path.read_bytes())
        info["AvailableLibraries"].append(info["AvailableLibraries"][0])
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            privacy.check_xcframework(package / "MarmotKit.xcframework")

    def test_static_archive_and_module_contract(self):
        for relative, contents, message in [
            ("MarmotKit.xcframework/ios-arm64/libmarmot_uniffi.a", b"dynamic!", "remain static"),
            ("MarmotKit.xcframework/ios-arm64/Headers/module.modulemap",
             b"framework module marmot_uniffiFFI {}", "original C module"),
        ]:
            with self.subTest(path=relative):
                package = self.fixture()
                (package / relative).write_bytes(contents)
                with self.assertRaisesRegex(ValueError, message):
                    privacy.check_xcframework(package / "MarmotKit.xcframework")
                shutil.rmtree(package)

    def test_extracted_xcframework_symlink_is_rejected(self):
        package = self.fixture()
        (package / "MarmotKit.xcframework/alias").symlink_to("Info.plist")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            privacy.check_xcframework(package / "MarmotKit.xcframework")

    def test_archive_linkage_ignores_own_path_but_rejects_dynamic_dependency(self):
        package = self.fixture("macos")
        archive = self.root / "MarmotKit-validation/Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        resource = app / "Contents/Resources/MarmotKit_MarmotKit.bundle/Contents/Resources/PrivacyInfo.xcprivacy"
        resource.parent.mkdir(parents=True)
        shutil.copyfile(package / "PrivacyInfo.xcprivacy", resource)
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Consumer"}))
        binary = app / "Contents/MacOS/Consumer"
        binary.parent.mkdir()
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"fixture")
        dsym = archive / "dSYMs/Consumer.app.dSYM/Contents/Resources/DWARF/Consumer"
        dsym.parent.mkdir(parents=True)
        dsym.write_bytes(b"fixture")
        dependency = "/usr/lib/libSystem.B.dylib"

        def output(args, **kwargs):
            if args[1] == "dwarfdump":
                return "UUID: 11111111-1111-1111-1111-111111111111 (arm64) fixture\n"
            if args[1] == "nm":
                return "00000001 T _uniffi_marmot_uniffi_fn_func_parse_media_imeta_tag\n"
            if args[1] == "otool":
                return f"{binary}:\n\t{dependency} (compatibility version 1.0.0)\n"
            self.fail(f"unexpected command: {args}")

        with mock.patch.object(privacy.subprocess, "check_output", side_effect=output):
            self.assertEqual(privacy.check_archive(archive, package / "PrivacyInfo.xcprivacy", "macos")["linking"], "static")
            for dependency in ["@rpath/MarmotKit.framework/MarmotKit",
                               "@rpath/marmot_uniffiFFI.framework/marmot_uniffiFFI"]:
                with self.subTest(dependency=dependency), self.assertRaisesRegex(ValueError, "statically linked"):
                    privacy.check_archive(archive, package / "PrivacyInfo.xcprivacy", "macos")

    def test_zip_roundtrip_and_unsafe_members(self):
        package = self.fixture()
        path = self.root / "artifact.zip"
        xc = package / "MarmotKit.xcframework"
        with zipfile.ZipFile(path, "w") as zipped:
            for file in xc.rglob("*"):
                if file.is_file():
                    zipped.write(file, file.relative_to(package))
        privacy.check_xcframework(privacy.extract_xcframework(path, self.root / "good"))
        for name in ["../outside", "MarmotKit.xcframework/../../outside", "/MarmotKit.xcframework/outside", "Other/file", "MarmotKit.xcframework/link"]:
            with self.subTest(name=name):
                with zipfile.ZipFile(path, "w") as zipped:
                    entry = zipfile.ZipInfo(name)
                    if name.endswith("link"):
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    zipped.writestr(entry, "../../outside")
                with self.assertRaises(ValueError):
                    privacy.extract_xcframework(path, self.root / "bad")
                shutil.rmtree(self.root / "bad")

    def test_main_app_cannot_stand_in_for_extension_privacy(self):
        package = self.fixture()
        archive = self.root / "Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        extension = app / "PlugIns/Notification.appex"
        extension.mkdir(parents=True)
        resource = app / "MarmotKit_MarmotKit.bundle/PrivacyInfo.xcprivacy"
        resource.parent.mkdir()
        shutil.copyfile(package / "PrivacyInfo.xcprivacy", resource)
        with self.assertRaisesRegex(ValueError, "privacy resource did not reach Notification.appex"):
            privacy.check_archive(archive, package / "PrivacyInfo.xcprivacy", "ios")

    def test_codeless_framework_is_rejected_with_privacy_present(self):
        package = self.fixture()
        archive = self.root / "Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        extension = app / "PlugIns/Notification.appex"
        for bundle in [app, extension]:
            resource = bundle / "MarmotKit_MarmotKit.bundle/PrivacyInfo.xcprivacy"
            resource.parent.mkdir(parents=True)
            shutil.copyfile(package / "PrivacyInfo.xcprivacy", resource)
        (app / "Frameworks/marmot_uniffiFFI.framework").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "stub"):
            privacy.check_archive(archive, package / "PrivacyInfo.xcprivacy", "ios")


if __name__ == "__main__":
    unittest.main()
