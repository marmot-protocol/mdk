#!/usr/bin/env python3
"""Build a real app archive using a local SwiftPM MarmotKit binary dependency.

Requires Xcode and XcodeGen. macOS uses ad-hoc signing; iOS is unsigned
(no development certificate/profile). No runtime network or consumer repo edits.
The app deliberately has no privacy resource or manual resource-copy build phase.
With --swiftpm-package, iOS also archives a real notification service extension.
Both consumer entry points reference the public Rust parser.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("swift_package", HERE / "apple-swift-package.py")
swift_package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(swift_package)


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=["ios", "macos"])
    parser.add_argument("artifact", type=Path, help="XCFramework or packaged SwiftPM ZIP")
    parser.add_argument("binding", type=Path, help="matching Swift binding; use - with --swiftpm-package")
    parser.add_argument("--swiftpm-package", action="store_true", help="consume the complete release package ZIP")
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
    if args.swiftpm_package:
        package = swift_package.extract_package(artifact, work / "extracted")
        analytics = None if args.product_analytics is None else args.product_analytics in ("1", "true")
        swift_package.check_package(package, args.privacy_dir.resolve(), analytics)
        metadata = json.loads((package / "manifest.json").read_text())
        if metadata["platform"] != args.platform:
            raise ValueError("package platform differs from consumer platform")
    else:
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
    var body: some Scene { WindowGroup { Text(rustProbe(ProcessInfo.processInfo.arguments.last ?? "probe")) } }
}
''')
    shared = work / "Shared"
    shared.mkdir()
    (shared / "Probe.swift").write_text('''import MarmotKit
func rustProbe(_ input: String) -> String {
    do {
        return String(describing: try parseMediaImetaTag(tag: MessageTagFfi(values: [input]), sourceEpoch: 0))
    } catch { return String(describing: error) }
}
''')
    platform = "iOS" if args.platform == "ios" else "macOS"
    minimum = (metadata[args.platform + "_deployment_target"] if args.swiftpm_package
               else "18.0" if args.platform == "ios" else "15.0")
    project = dict(name="PrivacyConsumer", packages={"MarmotKit": {"path": str(package)}},
                   targets={"PrivacyConsumer": dict(type="application", platform=platform,
                       deploymentTarget=minimum,
                       sources=["App", "Shared"], dependencies=[{"package": "MarmotKit"}],
                       settings={"base": dict(PRODUCT_BUNDLE_IDENTIFIER="org.marmot-protocol.privacy-consumer",
                           GENERATE_INFOPLIST_FILE="YES",
                           SWIFT_VERSION="6.0", ENABLE_USER_SCRIPT_SANDBOXING="YES",
                           DEBUG_INFORMATION_FORMAT="dwarf-with-dsym", LD_GENERATE_MAP_FILE="YES")})})
    if args.swiftpm_package and args.platform == "ios":
        extension = work / "Extension"
        extension.mkdir()
        (extension / "Service.swift").write_text('''import UserNotifications
final class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler handler: @escaping (UNNotificationContent) -> Void) {
        let content = request.content.mutableCopy() as! UNMutableNotificationContent
        content.body = rustProbe(request.content.body)
        handler(content)
    }
}
''')
        project["targets"]["NotificationService"] = dict(
            type="app-extension", platform="iOS", deploymentTarget=minimum, sources=["Extension", "Shared"],
            dependencies=[{"package": "MarmotKit"}], settings={"base": dict(
                PRODUCT_BUNDLE_IDENTIFIER="org.marmot-protocol.privacy-consumer.notification",
                GENERATE_INFOPLIST_FILE="YES", SWIFT_VERSION="6.0", APPLICATION_EXTENSION_API_ONLY="YES",
                SKIP_INSTALL="YES", DEBUG_INFORMATION_FORMAT="dwarf-with-dsym", LD_GENERATE_MAP_FILE="YES")},
            info={"path": "Extension/Info.plist", "properties": {"NSExtension": {
                "NSExtensionPointIdentifier": "com.apple.usernotifications.service",
                "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).NotificationService"}}})
        project["targets"]["PrivacyConsumer"]["dependencies"].append({"target": "NotificationService", "embed": True})
    project["settings"] = {"base": {"CURRENT_PROJECT_VERSION": "1", "MARKETING_VERSION": "1.0"}}
    (work / "project.json").write_text(json.dumps(project, indent=2))
    run("xcodegen", "generate", "--spec", "project.json", cwd=work)
    if args.swiftpm_package and args.platform == "ios":
        run("xcodebuild", "-project", "PrivacyConsumer.xcodeproj", "-scheme", "PrivacyConsumer",
            "-configuration", "Release", "-destination", "generic/platform=iOS Simulator",
            "-derivedDataPath", str(work / "DerivedData-simulator"), "ARCHS=arm64",
            "CODE_SIGNING_ALLOWED=NO", "-quiet", "build", cwd=work)
    archive = work / "PrivacyConsumer.xcarchive"
    # Device iOS signing needs a development identity/profile; this fixture must
    # remain usable on credential-free CI runners. macOS can exercise signing.
    signing = (["CODE_SIGN_IDENTITY=-", "CODE_SIGNING_REQUIRED=YES"]
               if args.platform == "macos" else ["CODE_SIGNING_ALLOWED=NO"])
    run("xcodebuild", "-project", "PrivacyConsumer.xcodeproj", "-scheme", "PrivacyConsumer",
        "-configuration", "Release", "-destination", f"generic/platform={platform}",
        "-derivedDataPath", str(work / "DerivedData"), "-archivePath", str(archive),
        "ARCHS=arm64", *signing, "-quiet", "archive", cwd=work)
    if args.swiftpm_package:
        report = swift_package.check_archive(archive, package, args.privacy_dir.resolve(), analytics)
        (work / "archive-checks.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    else:
        run("python3", str(HERE / "validate-apple-privacy.py"), str(artifact), "--archive", str(archive), *privacy_args)
    if args.platform == "macos":
        app_bundle = next((archive / "Products/Applications").glob("*.app"))
        run("codesign", "--verify", "--deep", "--strict", str(app_bundle))


if __name__ == "__main__":
    main()
