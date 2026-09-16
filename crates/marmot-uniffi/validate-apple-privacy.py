#!/usr/bin/env python3
"""Verify reviewed privacy declarations and static-library packaging and consumer resource delivery."""

import argparse
import importlib.util
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import stat
import subprocess
import zipfile
import plistlib

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("apple_privacy", HERE / "apple-privacy.py")
framework = importlib.util.module_from_spec(spec)
spec.loader.exec_module(framework)


def check_manifest(path, privacy_dir=HERE / "apple-privacy", analytics=None):
    with path.open("rb") as f:
        actual = plistlib.load(f)
    if type(actual.get("NSPrivacyTracking")) is not bool:
        raise ValueError("tracking must be Boolean")
    for row in actual.get("NSPrivacyCollectedDataTypes", []):
        allowed_types = {"UserID", "DeviceID", "PerformanceData", "OtherDiagnosticData",
                         "ProductInteraction", "Name", "Contacts", "PhotosorVideos",
                         "OtherUserContent", "OtherUserContactInfo", "CoarseLocation", "EmailsOrTextMessages"}
        if row.get("NSPrivacyCollectedDataType") not in {
                "NSPrivacyCollectedDataType" + value for value in allowed_types}:
            raise ValueError("unsupported data type")
        for key in ("NSPrivacyCollectedDataTypeLinked", "NSPrivacyCollectedDataTypeTracking"):
            if type(row.get(key)) is not bool:
                raise ValueError(f"{key} must be Boolean")
        purposes = row.get("NSPrivacyCollectedDataTypePurposes")
        if not isinstance(purposes, list) or not purposes or any(p not in {
                "NSPrivacyCollectedDataTypePurposeAppFunctionality",
                "NSPrivacyCollectedDataTypePurposeAnalytics"} for p in purposes):
            raise ValueError("unsupported purpose")
    if actual.get("NSPrivacyAccessedAPITypes") != [{
            "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp",
            "NSPrivacyAccessedAPITypeReasons": ["C617.1"]}]:
        raise ValueError("required-reason categories/reasons need review")
    # Exact reviewed values also reject unknown keys, invalid types, duplicate
    # categories, missing declarations, and unsupported reason/purpose strings.
    variants = (False, True) if analytics is None else (analytics,)
    if actual not in [framework.privacy_manifest(mode, privacy_dir) for mode in variants]:
        raise ValueError(f"unreviewed or incomplete privacy manifest: {path}")
    return actual


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def check_xcframework(path):
    """Require raw ARM64 archives; SDK resources belong to the Swift wrapper."""
    if any(p.is_symlink() for p in path.rglob("*")):
        raise ValueError("raw-library XCFramework must not contain symlinks")
    slices = plistlib.loads((path / "Info.plist").read_bytes())["AvailableLibraries"]
    identities = set()
    hashes = {}
    for entry in slices:
        identity = (entry["SupportedPlatform"], entry.get("SupportedPlatformVariant", ""))
        if identity in identities or entry["SupportedArchitectures"] != ["arm64"]:
            raise ValueError("unexpected or duplicate architecture/platform")
        identities.add(identity)
        identifier = entry["LibraryIdentifier"]
        if Path(identifier).name != identifier or identifier in ("", ".", ".."):
            raise ValueError("invalid XCFramework slice identifier")
        if entry["LibraryPath"] != "libmarmot_uniffi.a" or entry["HeadersPath"] != "Headers":
            raise ValueError("expected raw static-library slices")
        slice_dir = path / identifier
        library = slice_dir / entry["LibraryPath"]
        with library.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("library must remain static")
        hashes[f"MarmotKit.xcframework/{identifier}/{library.name}"] = digest(library)
        if not (slice_dir / "Headers" / (framework.NAME + ".h")).is_file():
            raise ValueError("missing generated C header")
        if not (slice_dir / "Headers/module.modulemap").read_text().startswith("module " + framework.NAME):
            raise ValueError("raw library must retain the original C module name")
    if identities not in ({("ios", ""), ("ios", "simulator")}, {("macos", "")}):
        raise ValueError("missing or unexpected platform slices")
    if list(path.rglob("*.framework")) or list(path.rglob("*.xcprivacy")):
        raise ValueError("privacy must be owned by the Swift wrapper, without framework resources")
    return hashes


def check_release(provenance, artifact, binding, resource, platform, privacy_dir, analytics):
    """Check the three downloaded inputs against one release manifest before use."""
    metadata = json.loads(provenance.read_text())
    if (metadata.get("distribution") != "static-library-and-privacy-v1"
            or metadata["name"] != "marmotkit-" + platform):
        raise ValueError("unexpected Apple release distribution/platform")
    if analytics != ("product-analytics-export" in metadata["features"]):
        raise ValueError("release features disagree with requested privacy declarations")
    for path in (artifact, binding, resource):
        if digest(path) != metadata["artifacts"][path.name]["sha256"]:
            raise ValueError("release input checksum mismatch: " + path.name)
    check_manifest(resource, privacy_dir, analytics)
    return metadata


def extract_xcframework(archive, destination):
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as zipped:
        seen = set()
        for entry in zipped.infolist():
            path = PurePosixPath(entry.filename)
            normalized = str(path)
            if (not path.parts or path.parts[0] != "MarmotKit.xcframework" or path.is_absolute()
                    or ".." in path.parts or "\\" in entry.filename or normalized in seen
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("invalid XCFramework ZIP member")
            seen.add(normalized)
        zipped.extractall(destination)
    return destination / "MarmotKit.xcframework"

def check_fixture_archive(archive, resource_file, platform, privacy_dir=HERE / "apple-privacy", analytics=None):
    """Check the generated fixture only: resources, static linkage and UUIDs; not Rust source lines."""
    expected = check_manifest(resource_file, privacy_dir, analytics)
    macos = platform == "macos"
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
        if not resource.is_file():
            raise ValueError(f"MarmotKit privacy resource did not reach {bundle.name}: {resource}")
        if check_manifest(resource, privacy_dir, analytics) != expected:
            raise ValueError("archived SDK privacy declarations differ from packaged source")
    if list(products.rglob(framework.NAME + ".framework")):
        raise ValueError("Swift wrapper resources must not embed the empty FFI framework stub")

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"])
    parser.add_argument("--privacy-dir", type=Path, default=HERE / "apple-privacy")
    args = parser.parse_args()
    analytics = None if args.product_analytics is None else args.product_analytics in ("1", "true")
    if args.artifact.suffix == ".xcprivacy":
        check_manifest(args.artifact, args.privacy_dir, analytics)
        print("Validated SDK privacy declarations (not resource delivery or App Store upload validation)")
    else:
        check_xcframework(args.artifact)
        print("Validated raw-library XCFramework (not privacy declarations or App Store upload validation)")
