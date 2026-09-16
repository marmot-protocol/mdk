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
spec = importlib.util.spec_from_file_location("swift_package", HERE / "apple-swift-package.py")
package_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_tools)


class SwiftPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, platform="ios", analytics=False):
        package = self.root / "MarmotKit"
        (package / "Sources/MarmotKit").mkdir(parents=True)
        (package / package_tools.BINDING).write_text("// generated Swift fixture\n")
        manifest = package_tools.privacy.framework.privacy_manifest(analytics)
        (package / package_tools.RESOURCE).write_bytes(plistlib.dumps(manifest))
        minimum = "18.0" if platform == "ios" else "15.0"
        (package / "Package.swift").write_text(package_tools.package_source(platform, minimum))
        xc = package / package_tools.XCFRAMEWORK
        entries = []
        hashes = {}
        variants = ["", "simulator"] if platform == "ios" else [""]
        for variant in variants:
            identifier = platform + "-arm64" + ("-" + variant if variant else "")
            slice_dir = xc / identifier
            (slice_dir / "Headers").mkdir(parents=True)
            library = slice_dir / "libmarmot_uniffi.a"
            library.write_bytes(b"!<arch>\nunchanged archive fixture")
            hashes[identifier] = package_tools.digest(library)
            (slice_dir / "Headers/marmot_uniffiFFI.h").write_text("void fixture(void);\n")
            (slice_dir / "Headers/module.modulemap").write_text('module marmot_uniffiFFI { header "marmot_uniffiFFI.h" }\n')
            entry = dict(LibraryIdentifier=identifier, LibraryPath=library.name, HeadersPath="Headers",
                         SupportedPlatform=platform, SupportedArchitectures=["arm64"])
            if variant:
                entry["SupportedPlatformVariant"] = variant
            entries.append(entry)
        (xc / "Info.plist").write_bytes(plistlib.dumps(dict(AvailableLibraries=entries)))
        metadata = dict(platform=platform, distribution="swiftpm-resources-v1",
                        features=["product-analytics-export"] if analytics else [],
                        source_library_sha256=hashes, generated_swift_sha256=package_tools.digest(package / package_tools.BINDING),
                        files=package_tools.file_hashes(package))
        metadata[platform + "_deployment_target"] = minimum
        (package / "manifest.json").write_text(json.dumps(metadata))
        return package

    def refresh_payload_hashes(self, package):
        path = package / "manifest.json"
        data = json.loads(path.read_text())
        data["files"] = package_tools.file_hashes(package)
        path.write_text(json.dumps(data))

    def test_all_platforms_and_feature_declarations(self):
        for platform in ["ios", "macos"]:
            for analytics in [False, True]:
                with self.subTest(platform=platform, analytics=analytics):
                    package = self.fixture(platform, analytics)
                    package_tools.check_package(package, analytics=analytics)
                    with self.assertRaises(ValueError):
                        package_tools.check_package(package, analytics=not analytics)
                    shutil.rmtree(package)

    def test_resource_missing_even_with_updated_file_inventory(self):
        package = self.fixture()
        (package / package_tools.RESOURCE).unlink()
        self.refresh_payload_hashes(package)
        with self.assertRaises(FileNotFoundError):
            package_tools.check_package(package)

    def test_manifest_not_declared_as_swiftpm_resource(self):
        package = self.fixture()
        path = package / "Package.swift"
        path.write_text(path.read_text().replace('resources: [.copy("PrivacyInfo.xcprivacy")],', ''))
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "declare"):
            package_tools.check_package(package)

    def test_changed_archive_cannot_claim_original_source_hash(self):
        package = self.fixture()
        library = next(package.rglob("*.a"))
        library.write_bytes(b"!<arch>\nchanged archive")
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "changed source library"):
            package_tools.check_package(package)

    def test_missing_slice_and_framework_regression(self):
        package = self.fixture()
        info_path = package / "MarmotKit.xcframework/Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        original = info_path.read_bytes()
        info["AvailableLibraries"].pop()
        info_path.write_bytes(plistlib.dumps(info))
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "lost a platform"):
            package_tools.check_package(package)
        info_path.write_bytes(original)
        (package / "marmot_uniffiFFI.framework").mkdir()
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "framework resources"):
            package_tools.check_package(package)

    def test_reviewed_source_not_builders_privacy_is_baseline(self):
        package = self.fixture()
        source = self.root / "source-privacy"
        shutil.copytree(HERE / "apple-privacy", source)
        data = plistlib.loads((source / "PrivacyInfo.xcprivacy").read_bytes())
        data["NSPrivacyCollectedDataTypes"].reverse()
        (source / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(data))
        (package / package_tools.RESOURCE).write_bytes(plistlib.dumps(data))
        self.refresh_payload_hashes(package)
        with self.assertRaises(ValueError):
            package_tools.check_package(package)
        package_tools.check_package(package, source, False)

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
                self.refresh_payload_hashes(package)
                with self.assertRaisesRegex(ValueError, message):
                    package_tools.check_package(package)
                shutil.rmtree(package)

    def test_duplicate_platform_is_rejected(self):
        package = self.fixture()
        path = package / "MarmotKit.xcframework/Info.plist"
        info = plistlib.loads(path.read_bytes())
        info["AvailableLibraries"].append(info["AvailableLibraries"][0])
        path.write_bytes(plistlib.dumps(info))
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            package_tools.check_package(package)

    def test_payload_contract_survives_refreshed_inventory(self):
        for relative, contents, message in [
            ("MarmotKit.xcframework/ios-arm64/libmarmot_uniffi.a", b"dynamic!", "remain static"),
            ("MarmotKit.xcframework/ios-arm64/Headers/module.modulemap",
             b"framework module marmot_uniffiFFI {}", "original C module"),
            (package_tools.BINDING, b"// wrong generated binding", "binding mismatch"),
        ]:
            with self.subTest(path=relative):
                package = self.fixture()
                (package / relative).write_bytes(contents)
                self.refresh_payload_hashes(package)
                with self.assertRaisesRegex(ValueError, message):
                    package_tools.check_package(package)
                shutil.rmtree(package)

    def test_extracted_package_symlink_is_rejected(self):
        package = self.fixture()
        (package / "alias.swift").symlink_to(package_tools.BINDING)
        self.refresh_payload_hashes(package)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            package_tools.check_package(package)

    def test_archive_linkage_ignores_own_path_but_rejects_dynamic_dependency(self):
        package = self.fixture("macos")
        archive = self.root / "MarmotKit-validation/Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        resource = app / "Contents/Resources/MarmotKit_MarmotKit.bundle/Contents/Resources/PrivacyInfo.xcprivacy"
        resource.parent.mkdir(parents=True)
        shutil.copyfile(package / package_tools.RESOURCE, resource)
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

        with mock.patch.object(package_tools.subprocess, "check_output", side_effect=output):
            self.assertEqual(package_tools.check_archive(archive, package)["linking"], "static")
            for dependency in ["@rpath/MarmotKit.framework/MarmotKit",
                               "@rpath/marmot_uniffiFFI.framework/marmot_uniffiFFI"]:
                with self.subTest(dependency=dependency), self.assertRaisesRegex(ValueError, "statically linked"):
                    package_tools.check_archive(archive, package)

    def test_zip_round_trip_and_unsafe_entries(self):
        package = self.fixture()
        path = self.root / "package.zip"
        with zipfile.ZipFile(path, "w") as zipped:
            for file in package.rglob("*"):
                if file.is_file():
                    zipped.write(file, file.relative_to(self.root))
        unpacked = package_tools.extract_package(path, self.root / "good")
        package_tools.check_package(unpacked)
        for name in ["../outside", "MarmotKit/../../outside", "/MarmotKit/outside", "Other/file", "MarmotKit/link"]:
            with self.subTest(name=name):
                with zipfile.ZipFile(path, "w") as zipped:
                    entry = zipfile.ZipInfo(name)
                    if name.endswith("link"):
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    zipped.writestr(entry, "../../outside")
                with self.assertRaises(ValueError):
                    package_tools.extract_package(path, self.root / "bad")
                shutil.rmtree(self.root / "bad")

    def test_main_app_cannot_stand_in_for_extension_privacy(self):
        package = self.fixture()
        archive = self.root / "Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        extension = app / "PlugIns/Notification.appex"
        extension.mkdir(parents=True)
        resource = app / "MarmotKit_MarmotKit.bundle/PrivacyInfo.xcprivacy"
        resource.parent.mkdir()
        shutil.copyfile(package / package_tools.RESOURCE, resource)
        with self.assertRaisesRegex(ValueError, "privacy resource did not reach Notification.appex"):
            package_tools.check_archive(archive, package)

    def test_codeless_framework_is_rejected_with_privacy_present(self):
        package = self.fixture()
        archive = self.root / "Consumer.xcarchive"
        app = archive / "Products/Applications/Consumer.app"
        extension = app / "PlugIns/Notification.appex"
        for bundle in [app, extension]:
            resource = bundle / "MarmotKit_MarmotKit.bundle/PrivacyInfo.xcprivacy"
            resource.parent.mkdir(parents=True)
            shutil.copyfile(package / package_tools.RESOURCE, resource)
        (app / "Frameworks/marmot_uniffiFFI.framework").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "stub"):
            package_tools.check_archive(archive, package)


if __name__ == "__main__":
    unittest.main()
