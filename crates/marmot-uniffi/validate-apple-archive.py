#!/usr/bin/env python3
"""Build a real app archive using a local SwiftPM MarmotKit binary dependency.

Requires Xcode and XcodeGen. No signing, networking at runtime, or consumer repo edits.
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
    parser.add_argument("artifact", type=Path)
    parser.add_argument("binding", type=Path)
    parser.add_argument("work", type=Path, help="new directory; retained for inspection")
    args = parser.parse_args()
    artifact, binding, work = args.artifact.resolve(), args.binding.resolve(), args.work.resolve()
    if not shutil.which("xcodegen"):
        parser.error("XcodeGen required (brew install xcodegen)")
    run("python3", str(HERE / "validate-apple-privacy.py"), str(artifact))
    work.mkdir(parents=True, exist_ok=False)
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
                           GENERATE_INFOPLIST_FILE="YES", CODE_SIGNING_ALLOWED="NO",
                           SWIFT_VERSION="6.0", ENABLE_USER_SCRIPT_SANDBOXING="YES")})})
    (work / "project.json").write_text(json.dumps(project, indent=2))
    run("xcodegen", "generate", "--spec", "project.json", cwd=work)
    archive = work / "PrivacyConsumer.xcarchive"
    run("xcodebuild", "-project", "PrivacyConsumer.xcodeproj", "-scheme", "PrivacyConsumer",
        "-configuration", "Release", "-destination", f"generic/platform={platform}",
        "-derivedDataPath", str(work / "DerivedData"), "-archivePath", str(archive),
        "ARCHS=arm64", "CODE_SIGNING_ALLOWED=NO", "-quiet", "archive", cwd=work)
    run("python3", str(HERE / "validate-apple-privacy.py"), str(artifact), "--archive", str(archive))


if __name__ == "__main__":
    main()
