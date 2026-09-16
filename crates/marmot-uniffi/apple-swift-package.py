#!/usr/bin/env python3
"""Package unchanged static archives with SwiftPM-owned privacy resources.

The existing resource-bearing framework distribution remains supported. This
additional, complete local Swift package avoids embedding a codeless framework.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("privacy", HERE / "validate-apple-privacy.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)
NAME = "marmot_uniffiFFI"
RESOURCE = "Sources/MarmotKit/PrivacyInfo.xcprivacy"
BINDING = "Sources/MarmotKit/MarmotKit.swift"
XCFRAMEWORK = "MarmotKit.xcframework"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def package_source(platform, minimum):
    # Only the declared platform has matching binary slices. macOS needs these
    # system frameworks for the native code linked into the final consumer.
    if platform not in ("ios", "macos") or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", minimum):
        raise ValueError("invalid package platform or deployment target")
    declaration = ".iOS" if platform == "ios" else ".macOS"
    return f'''// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "MarmotKit",
    platforms: [{declaration}("{minimum}")],
    products: [.library(name: "MarmotKit", targets: ["MarmotKit"])],
    targets: [
        .binaryTarget(name: "MarmotKitFFI", path: "MarmotKit.xcframework"),
        .target(
            name: "MarmotKit",
            dependencies: ["MarmotKitFFI"],
            resources: [.copy("PrivacyInfo.xcprivacy")],
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.macOS])),
                .linkedFramework("SystemConfiguration", .when(platforms: [.macOS]))
            ]
        )
    ]
)
'''


def file_hashes(package):
    return {p.relative_to(package).as_posix(): digest(p)
            for p in sorted(package.rglob("*")) if p.is_file() and p != package / "manifest.json"}


def check_package(package, privacy_dir=HERE / "apple-privacy", analytics=None):
    manifest = json.loads((package / "manifest.json").read_text())
    platform = manifest["platform"]
    if platform not in ("ios", "macos") or manifest["distribution"] != "swiftpm-resources-v1":
        raise ValueError("unexpected SwiftPM package distribution")
    if any(p.is_symlink() for p in package.rglob("*")):
        raise ValueError("raw-library SwiftPM package must not contain symlinks")
    if file_hashes(package) != manifest["files"]:
        raise ValueError("package contents do not match provenance hashes")
    minimum = manifest[platform + "_deployment_target"]
    if (package / "Package.swift").read_text() != package_source(platform, minimum):
        raise ValueError("package must declare its matching binary, source and privacy resource")
    expected_analytics = "product-analytics-export" in manifest["features"]
    if analytics is not None and analytics != expected_analytics:
        raise ValueError("package features disagree with requested privacy declarations")
    expected = privacy.check_manifest(package / RESOURCE, privacy_dir, expected_analytics)
    with (package / XCFRAMEWORK / "Info.plist").open("rb") as stream:
        slices = plistlib.load(stream)["AvailableLibraries"]
    required = {("ios", ""), ("ios", "simulator")} if platform == "ios" else {("macos", "")}
    actual = set()
    library_hashes = {}
    for entry in slices:
        identity = (entry["SupportedPlatform"], entry.get("SupportedPlatformVariant", ""))
        if identity in actual or entry["SupportedArchitectures"] != ["arm64"]:
            raise ValueError("unexpected or duplicate package architecture/platform")
        actual.add(identity)
        identifier = entry["LibraryIdentifier"]
        if Path(identifier).name != identifier or identifier in ("", ".", ".."):
            raise ValueError("invalid XCFramework slice identifier")
        if entry["LibraryPath"] != "libmarmot_uniffi.a" or entry["HeadersPath"] != "Headers":
            raise ValueError("SwiftPM resource package requires raw static-library slices")
        root = package / XCFRAMEWORK / identifier
        library = root / entry["LibraryPath"]
        with library.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("SwiftPM package library must remain static")
        library_hashes[identifier] = digest(library)
        if not (root / "Headers" / (NAME + ".h")).is_file():
            raise ValueError("missing generated C header")
        modulemap = (root / "Headers/module.modulemap").read_text()
        if not modulemap.startswith("module " + NAME):
            raise ValueError("raw library must retain the original C module name")
    if actual != required or library_hashes != manifest["source_library_sha256"]:
        raise ValueError("package lost a platform or changed source library bytes")
    if list(package.rglob("*.framework")) or list(package.rglob("*.xcprivacy")) != [package / RESOURCE]:
        raise ValueError("privacy must be owned by the Swift target, without framework resources")
    if digest(package / BINDING) != manifest["generated_swift_sha256"]:
        raise ValueError("generated binding mismatch")
    return expected


def extract_package(archive, destination):
    """Extract only the complete package contract; never follow archive symlinks."""
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as zipped:
        seen = set()
        for entry in zipped.infolist():
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (not path.parts or path.parts[0] != "MarmotKit" or path.is_absolute()
                    or ".." in path.parts or "\\" in entry.filename or entry.filename in seen
                    or stat.S_ISLNK(mode)):
                raise ValueError("invalid SwiftPM package ZIP member")
            seen.add(entry.filename)
        zipped.extractall(destination)
    return destination / "MarmotKit"


def check_archive(archive, package, privacy_dir=HERE / "apple-privacy", analytics=None):
    """Check resource ownership, static linkage and UUIDs; not Rust source lines."""
    expected = check_package(package, privacy_dir, analytics)
    metadata = json.loads((package / "manifest.json").read_text())
    macos = metadata["platform"] == "macos"
    products = archive / "Products/Applications"
    apps = list(products.glob("*.app"))
    if len(apps) != 1:
        raise ValueError("expected exactly one app")
    app = apps[0]
    extensions = [] if macos else list(app.glob("PlugIns/*.appex"))
    if not macos and len(extensions) != 1:
        raise ValueError("iOS fixture must contain its notification extension")
    for bundle in [app, *extensions]:
        resources = bundle / "Contents/Resources" if macos else bundle
        resource_bundle = resources / "MarmotKit_MarmotKit.bundle"
        resource = resource_bundle / ("Contents/Resources" if macos else "") / "PrivacyInfo.xcprivacy"
        if privacy.check_manifest(resource, privacy_dir, analytics) != expected:
            raise ValueError("archived SDK privacy declarations differ from packaged source")
    if list(products.rglob(NAME + ".framework")):
        raise ValueError("SwiftPM resource package must not embed the empty FFI framework stub")

    def run(*args):
        return subprocess.check_output([str(arg) for arg in args], text=True)

    def uuids(path):
        return set(re.findall(r"UUID: ([0-9A-F-]+) \(([^)]+)\)", run("xcrun", "dwarfdump", "--uuid", path)))

    symbols = list((archive / "dSYMs").glob("*.dSYM/Contents/Resources/DWARF/*"))
    symbol_ids = {path: uuids(path) for path in symbols}
    images = []
    for path in products.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            magic = stream.read(8)
        if magic == b"!<arch>\n":
            raise ValueError("a development static archive was embedded in the app")
        if magic[:4] not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            continue
        identities = uuids(path)
        if not identities or not any(identities <= ids for ids in symbol_ids.values()):
            raise ValueError("archive image lacks UUID-matched dSYM: " + str(path))
        images.append(dict(path=str(path.relative_to(archive)), uuids=sorted(identities)))
    if len(images) != (1 if macos else 2):
        raise ValueError("fixture must contain only its statically linked consumer executables")
    for bundle in [app, *extensions]:
        info_path = bundle / "Contents/Info.plist" if macos else bundle / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        binary = bundle / ("Contents/MacOS" if macos else "") / info["CFBundleExecutable"]
        if not macos and bundle != app:
            if info.get("NSExtension", {}).get("NSExtensionPointIdentifier") != "com.apple.usernotifications.service":
                raise ValueError("expected a notification service extension")
        binary_ids = uuids(binary)
        matched = [path for path, ids in symbol_ids.items() if binary_ids == ids]
        if len(matched) != 1:
            raise ValueError("consumer dSYM missing or ambiguous")
        names = run("xcrun", "nm", "-nm", matched[0])
        if not re.search(r"^[0-9a-fA-F]+ .* _uniffi_marmot_uniffi_fn_func_parse_media_imeta_tag$", names, re.M):
            raise ValueError("real Rust parser was not linked into the consumer")
        # otool's first line names the inspected binary, not a dependency.
        dependencies = run("xcrun", "otool", "-L", binary).splitlines()[1:]
        if any("marmot_uniffi" in line or "MarmotKit" in line for line in dependencies):
            raise ValueError("MarmotKit must remain statically linked")
    return dict(validation="local archive only; export and upload not validated", images=images,
                privacy_resources="matched in every consumer", linking="static", rust_debug_policy="unchanged")


def build_package(artifact, binding, provenance, output, privacy_dir, analytics):
    expected = privacy.check_xcframework(artifact, privacy_dir, analytics)
    original = json.loads(provenance.read_text())
    platform = original["name"].removeprefix("marmotkit-")
    if platform not in ("ios", "macos"):
        raise ValueError("unsupported source manifest")
    if analytics != ("product-analytics-export" in original["features"]):
        raise ValueError("source manifest features disagree with privacy feature selection")
    swift_key = "MarmotKit-" + original["release_identifier"] + ".swift"
    if digest(binding) != original["artifacts"][swift_key]["sha256"]:
        raise ValueError("generated Swift does not match source provenance")
    minimum = original[platform + "_deployment_target"]
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp)
        package = stage / "MarmotKit"
        (package / "Sources/MarmotKit").mkdir(parents=True)
        shutil.copyfile(binding, package / BINDING)
        (package / RESOURCE).write_bytes(plistlib.dumps(expected, sort_keys=False))
        (package / "Package.swift").write_text(package_source(platform, minimum))
        slices = plistlib.loads((artifact / "Info.plist").read_bytes())["AvailableLibraries"]
        inputs = []
        library_hashes = {}
        for entry in slices:
            identifier = entry["LibraryIdentifier"]
            source = artifact / identifier / entry["LibraryPath"]
            target = stage / "libraries" / identifier
            target.mkdir(parents=True)
            shutil.copyfile(source / NAME, target / "libmarmot_uniffi.a")
            shutil.copytree(source / "Headers", target / "Headers")
            modulemap = (source / "Modules/module.modulemap").read_text()
            if not modulemap.startswith("framework module " + NAME):
                raise ValueError("unexpected generated framework module map")
            (target / "Headers/module.modulemap").write_text(modulemap.removeprefix("framework "))
            source_key = f"MarmotKit.xcframework/{identifier}/{entry['BinaryPath']}"
            library_hashes[identifier] = digest(target / "libmarmot_uniffi.a")
            if library_hashes[identifier] != original["artifacts"][source_key]["sha256"]:
                raise ValueError("source archive does not match release provenance")
            inputs.extend(["-library", str(target / "libmarmot_uniffi.a"),
                           "-headers", str(target / "Headers")])
        subprocess.run(["xcodebuild", "-create-xcframework", *inputs,
                        "-output", str(package / XCFRAMEWORK)], check=True)
        # This is a distinct distribution manifest. Retain source/build/profile
        # identity, replace the old framework payload inventory with this one.
        # distribution versions this contract independently of the framework schema.
        manifest = {k: v for k, v in original.items()
                    if k not in ("schema_version", "artifacts", "contents", "swiftpm_package")}
        manifest.update(name="marmotkit-swiftpm-" + platform, platform=platform,
                        distribution="swiftpm-resources-v1", source_library_sha256=library_hashes,
                        generated_swift_sha256=digest(binding), files=file_hashes(package))
        (package / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        check_package(package, privacy_dir, analytics)
        # Write only local build output; immutable publishing is
        # handled by the existing release workflow, never by this helper.
        staged_zip = stage / "package.zip"
        with zipfile.ZipFile(staged_zip, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for path in sorted(package.rglob("*")):
                if path.is_file():
                    zipped.write(path, path.relative_to(stage))
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staged_zip, output)
    checksum = digest(output)
    output.with_name(output.name + ".sha256").write_text(f"{checksum}  {output.name}\n")
    original["swiftpm_package"] = dict(name=output.name, sha256=checksum,
                                      distribution="swiftpm-resources-v1")
    provenance.write_text(json.dumps(original, indent=2) + "\n")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("binding", type=Path)
    parser.add_argument("provenance", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--privacy-dir", type=Path, required=True)
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"], required=True)
    args = parser.parse_args()
    build_package(args.artifact.resolve(), args.binding.resolve(), args.provenance.resolve(),
                  args.output.resolve(), args.privacy_dir.resolve(), args.product_analytics in ("1", "true"))
