#!/usr/bin/env python3
"""Build a real app archive using a local SwiftPM MarmotKit binary dependency.

Requires Xcode and XcodeGen. macOS uses ad-hoc signing; iOS is unsigned
(no development certificate/profile). No runtime network or consumer repo edits.
The app deliberately has no privacy resource or manual resource-copy build phase.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=["ios", "macos"])
    parser.add_argument("artifact", type=Path, help="XCFramework or packaged SwiftPM ZIP")
    parser.add_argument("binding", type=Path)
    parser.add_argument("work", type=Path, help="new directory; retained for inspection")
    parser.add_argument("--privacy-dir", type=Path, default=HERE / "apple-privacy")
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"])
    args = parser.parse_args()
    artifact, binding, work = args.artifact.resolve(), args.binding.resolve(), args.work.resolve()
    if not shutil.which("xcodegen"):
        parser.error("XcodeGen required (brew install xcodegen)")
    privacy_args = ["--privacy-dir", str(args.privacy_dir.resolve())]
    if args.product_analytics is not None:
        privacy_args += ["--product-analytics", args.product_analytics]
    work.mkdir(parents=True, exist_ok=False)
    if artifact.suffix == ".zip":
        entries = subprocess.check_output(["unzip", "-Z1", str(artifact)], text=True).splitlines()
        if not entries or any(Path(e).parts[0] != "MarmotKit.xcframework" or ".." in Path(e).parts for e in entries):
            raise ValueError("SwiftPM ZIP must contain only MarmotKit.xcframework at its root")
        run("unzip", "-q", str(artifact), "-d", str(work / "extracted"))
        artifact = work / "extracted/MarmotKit.xcframework"
    run("python3", str(HERE / "validate-apple-privacy.py"), str(artifact), *privacy_args)
    package = work / "MarmotKit"
    source = package / "Sources/MarmotKit"
    source.mkdir(parents=True)
    shutil.copyfile(binding, source / "MarmotKit.swift")
    shutil.copytree(artifact, package / "MarmotKit.xcframework", symlinks=True)
    (package / "Package.swift").write_text('''// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "MarmotKit", platforms: [.iOS(.v18), .macOS(.v15)],
    products: [.library(name: "MarmotKit", targets: ["MarmotKit"])],
    targets: [
        .binaryTarget(name: "MarmotKitFFI", path: "MarmotKit.xcframework"),
        .target(name: "MarmotKit", dependencies: ["MarmotKitFFI"])
    ])
''')
    app = work / "App"
    app.mkdir()
    (app / "Consumer.swift").write_text('''import SwiftUI
import MarmotKit
@main struct PrivacyConsumer: App {
    var body: some Scene { WindowGroup { Text(String(describing: Marmot.self)) } }
}
''')
    platform = "iOS" if args.platform == "ios" else "macOS"
    project = dict(name="PrivacyConsumer", packages={"MarmotKit": {"path": "MarmotKit"}},
                   targets={"PrivacyConsumer": dict(type="application", platform=platform,
                       deploymentTarget="18.0" if args.platform == "ios" else "15.0",
                       sources=["App"], dependencies=[{"package": "MarmotKit"}],
                       settings={"base": dict(PRODUCT_BUNDLE_IDENTIFIER="org.marmot-protocol.privacy-consumer",
                           GENERATE_INFOPLIST_FILE="YES",
                           SWIFT_VERSION="6.0", ENABLE_USER_SCRIPT_SANDBOXING="YES")})})
    (work / "project.json").write_text(json.dumps(project, indent=2))
    run("xcodegen", "generate", "--spec", "project.json", cwd=work)
    archive = work / "PrivacyConsumer.xcarchive"
    # Device iOS signing needs a development identity/profile; this fixture must
    # remain usable on credential-free CI runners. macOS can exercise signing.
    signing = (["CODE_SIGN_IDENTITY=-", "CODE_SIGNING_REQUIRED=YES"]
               if args.platform == "macos" else ["CODE_SIGNING_ALLOWED=NO"])
    run("xcodebuild", "-project", "PrivacyConsumer.xcodeproj", "-scheme", "PrivacyConsumer",
        "-configuration", "Release", "-destination", f"generic/platform={platform}",
        "-derivedDataPath", str(work / "DerivedData"), "-archivePath", str(archive),
        "ARCHS=arm64", *signing, "-quiet", "archive", cwd=work)
    run("python3", str(HERE / "validate-apple-privacy.py"), str(artifact), "--archive", str(archive), *privacy_args)
    if args.platform == "macos":
        app_bundle = next((archive / "Products/Applications").glob("*.app"))
        run("codesign", "--verify", "--deep", "--strict", str(app_bundle))


if __name__ == "__main__":
    main()
