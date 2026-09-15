#!/usr/bin/env python3
"""Verify reviewed privacy declarations and their framework/archive placement."""

import argparse
import importlib.util
from pathlib import Path
import plistlib

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("apple_framework", HERE / "apple-framework.py")
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


def check_xcframework(path, privacy_dir=HERE / "apple-privacy", analytics=None):
    with (path / "Info.plist").open("rb") as f:
        slices = plistlib.load(f)["AvailableLibraries"]
    if not slices:
        raise ValueError("XCFramework has no slices")
    manifests = []
    for entry in slices:
        bundle = path / entry["LibraryIdentifier"] / entry["LibraryPath"]
        if bundle.name != framework.NAME + ".framework":
            raise ValueError("MarmotKit requires resource-bearing static framework slices")
        resource = bundle / ("Resources" if entry["SupportedPlatform"] == "macos" else "")
        manifests.append(check_manifest(resource / "PrivacyInfo.xcprivacy", privacy_dir, analytics))
        if entry["SupportedPlatform"] == "macos":
            for name in ("Versions/Current", framework.NAME, "Headers", "Modules", "Resources"):
                if not (bundle / name).is_symlink():
                    raise ValueError(f"missing versioned framework symlink: {bundle / name}")
        with (bundle / framework.NAME).open("rb") as f:
            if f.read(8) != b"!<arch>\n":
                raise ValueError(f"expected an unchanged static archive: {bundle}")
        for relative in [f"Headers/{framework.NAME}.h", "Modules/module.modulemap"]:
            if not (bundle / relative).is_file():
                raise ValueError(f"missing {bundle / relative}")
    if any(m != manifests[0] for m in manifests):
        raise ValueError("privacy declarations differ across slices")
    return manifests[0]


def check_archive(path, artifact, privacy_dir=HERE / "apple-privacy", analytics=None):
    expected = check_xcframework(artifact, privacy_dir, analytics)
    apps = list((path / "Products/Applications").glob("*.app"))
    if len(apps) != 1:
        raise ValueError("expected one consuming app in archive")
    # Require the SDK's framework in the main app. A host manifest or a copy
    # only in an extension, DerivedData, or the input artifact cannot satisfy it.
    macos = (apps[0] / "Contents").is_dir()
    bundle = apps[0] / ("Contents/Frameworks" if macos else "Frameworks") / (framework.NAME + ".framework")
    manifest = bundle / ("Resources" if macos else "") / "PrivacyInfo.xcprivacy"
    if not manifest.is_file():
        raise ValueError("MarmotKit privacy resource did not reach the archived app")
    if check_manifest(manifest, privacy_dir, analytics) != expected:
        raise ValueError("archived SDK privacy resource differs from the input artifact")
    for binary in apps[0].rglob(framework.NAME):
        if binary.is_file():
            with binary.open("rb") as f:
                if f.read(8) == b"!<arch>\n":
                    raise ValueError("Xcode must omit the static archive from the embedded framework")
    print(f"Archived MarmotKit manifest: {manifest.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"])
    parser.add_argument("--privacy-dir", type=Path, default=HERE / "apple-privacy")
    args = parser.parse_args()
    analytics = None if args.product_analytics is None else args.product_analytics in ("1", "true")
    if args.archive:
        check_archive(args.archive, args.artifact, args.privacy_dir, analytics)
    elif args.artifact.suffix == ".xcprivacy":
        check_manifest(args.artifact, args.privacy_dir, analytics)
    else:
        check_xcframework(args.artifact, args.privacy_dir, analytics)
    print("Validated MarmotKit privacy resources (not App Store upload validation)")
