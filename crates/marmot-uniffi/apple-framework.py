#!/usr/bin/env python3
"""Stage Cargo's unmodified archive as an Apple static framework with resources."""

import argparse
import hashlib
from pathlib import Path
import plistlib
import shutil

HERE = Path(__file__).resolve().parent
NAME = "marmot_uniffiFFI"


def privacy_manifest(analytics=False, privacy_dir=HERE / "apple-privacy"):
    with (privacy_dir / "PrivacyInfo.xcprivacy").open("rb") as f:
        manifest = plistlib.load(f)
    if analytics:
        with (privacy_dir / "product-analytics.plist").open("rb") as f:
            additions = plistlib.load(f)["NSPrivacyCollectedDataTypes"]
        rows = {r["NSPrivacyCollectedDataType"]: r for r in manifest["NSPrivacyCollectedDataTypes"]}
        for row in additions:
            key = row["NSPrivacyCollectedDataType"]
            if key in rows:
                rows[key]["NSPrivacyCollectedDataTypePurposes"] += row["NSPrivacyCollectedDataTypePurposes"]
            else:
                manifest["NSPrivacyCollectedDataTypes"].append(row)
    return manifest


def stage(library, headers, output, platform, minimum, analytics, privacy_dir):
    # Refuse reuse: this helper must never patch an expanded consumer artifact.
    output.mkdir(parents=True, exist_ok=False)
    root = output
    resources = root
    if platform == "macos":
        root = output / "Versions/A"
        resources = root / "Resources"
        resources.mkdir(parents=True)
        (output / "Versions/Current").symlink_to("A")
        for name in (NAME, "Headers", "Modules", "Resources"):
            (output / name).symlink_to("Versions/Current/" + name)
    (root / "Headers").mkdir()
    (root / "Modules").mkdir()
    shutil.copyfile(library, root / NAME)
    def digest(path):
        value = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(chunk)
        return value.digest()
    if digest(library) != digest(root / NAME):
        raise ValueError("framework staging changed Cargo archive bytes")
    shutil.copyfile(headers / (NAME + ".h"), root / "Headers" / (NAME + ".h"))
    # Keep the generated C module's name and declarations; only its packaging changes.
    modulemap = (headers / "module.modulemap").read_text()
    if not modulemap.startswith("module " + NAME):
        raise ValueError("unexpected generated UniFFI module map")
    (root / "Modules/module.modulemap").write_text("framework " + modulemap)
    info = dict(CFBundleIdentifier="org.marmot-protocol.MarmotKitFFI",
                CFBundleName=NAME, CFBundleExecutable=NAME, CFBundlePackageType="FMWK",
                CFBundleVersion="1", CFBundleShortVersionString="1.0")
    info["LSMinimumSystemVersion" if platform == "macos" else "MinimumOSVersion"] = minimum
    (resources / "Info.plist").write_bytes(plistlib.dumps(info))
    (resources / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps(privacy_manifest(analytics, privacy_dir), sort_keys=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("headers", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("platform", choices=["ios", "macos"])
    parser.add_argument("minimum")
    parser.add_argument("--privacy-dir", type=Path, required=True)
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"], required=True)
    args = vars(parser.parse_args())
    args["analytics"] = args.pop("product_analytics") in ("1", "true")
    stage(**args)
