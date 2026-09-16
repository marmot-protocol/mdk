#!/usr/bin/env python3
"""Build a real app archive from released binary, Swift and privacy assets.

Requires Xcode and XcodeGen. macOS uses ad-hoc signing; iOS is unsigned
(no development certificate/profile). No runtime network or consumer repo edits.
The app deliberately has no privacy resource or manual resource-copy build phase.
iOS also archives a real notification service extension.
Both consumer entry points reference the public Rust parser.
"""

import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("privacy", HERE / "validate-apple-privacy.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=["ios", "macos"])
    parser.add_argument("artifact", type=Path, help="released binary-target XCFramework ZIP")
    parser.add_argument("binding", type=Path, help="matching released Swift binding")
    parser.add_argument("work", type=Path, help="new directory; retained for inspection")
    parser.add_argument("--privacy-manifest", type=Path, required=True, help="released platform privacy asset")
    parser.add_argument("--release-manifest", type=Path, required=True, help="matching platform provenance manifest")
    parser.add_argument("--privacy-dir", type=Path, default=HERE / "apple-privacy")
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"], required=True)
    args = parser.parse_args()
    artifact, binding, work = args.artifact.resolve(), args.binding.resolve(), args.work.resolve()
    resource = args.privacy_manifest.resolve()
    analytics = args.product_analytics in ("1", "true")
    if not shutil.which("xcodegen"):
        parser.error("XcodeGen required (brew install xcodegen)")
    metadata = privacy.check_release(args.release_manifest, artifact, binding, resource,
                                     args.platform, args.privacy_dir.resolve(), analytics)
    work.mkdir(parents=True, exist_ok=False)
    artifact = privacy.extract_xcframework(artifact, work / "extracted")
    hashes = privacy.check_xcframework(artifact)
    for name, value in hashes.items():
        if name not in metadata["artifacts"]:
            raise ValueError("release manifest does not describe this static-library layout: " + name)
        if metadata["artifacts"][name]["sha256"] != value:
            raise ValueError("static library differs from release provenance")
    package = work / "MarmotKit"
    source = package / "Sources/MarmotKit"
    source.mkdir(parents=True)
    shutil.copyfile(binding, source / "MarmotKit.swift")
    shutil.copyfile(resource, source / "PrivacyInfo.xcprivacy")
    shutil.copytree(artifact, package / "MarmotKit.xcframework")
    minimum = metadata[args.platform + "_deployment_target"]
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", minimum):
        raise ValueError("invalid deployment target")
    declaration = ".iOS" if args.platform == "ios" else ".macOS"
    (package / "Package.swift").write_text('''// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "MarmotKit", platforms: [PLATFORM("MINIMUM")],
    products: [.library(name: "MarmotKit", targets: ["MarmotKit"])],
    targets: [
        .binaryTarget(name: "MarmotKitFFI", path: "MarmotKit.xcframework"),
        .target(name: "MarmotKit", dependencies: ["MarmotKitFFI"],
            resources: [.copy("PrivacyInfo.xcprivacy")],
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.macOS])),
                .linkedFramework("SystemConfiguration", .when(platforms: [.macOS]))
            ])
    ])
'''.replace("PLATFORM", declaration).replace("MINIMUM", minimum))
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
    project = dict(name="PrivacyConsumer", packages={"MarmotKit": {"path": str(package)}},
                   targets={"PrivacyConsumer": dict(type="application", platform=platform,
                       deploymentTarget=minimum,
                       sources=["App", "Shared"], dependencies=[{"package": "MarmotKit"}],
                       settings={"base": dict(PRODUCT_BUNDLE_IDENTIFIER="org.marmot-protocol.privacy-consumer",
                           GENERATE_INFOPLIST_FILE="YES",
                           SWIFT_VERSION="6.0", ENABLE_USER_SCRIPT_SANDBOXING="YES",
                           DEBUG_INFORMATION_FORMAT="dwarf-with-dsym")})})
    if args.platform == "ios":
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
                SKIP_INSTALL="YES", DEBUG_INFORMATION_FORMAT="dwarf-with-dsym")},
            info={"path": "Extension/Info.plist", "properties": {"NSExtension": {
                "NSExtensionPointIdentifier": "com.apple.usernotifications.service",
                "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).NotificationService"}}})
        project["targets"]["PrivacyConsumer"]["dependencies"].append({"target": "NotificationService", "embed": True})
    project["settings"] = {"base": {"CURRENT_PROJECT_VERSION": "1", "MARKETING_VERSION": "1.0"}}
    (work / "project.json").write_text(json.dumps(project, indent=2))
    run("xcodegen", "generate", "--spec", "project.json", cwd=work)
    if args.platform == "ios":
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
    report = privacy.check_fixture_archive(archive, resource, args.platform, args.privacy_dir.resolve(), analytics)
    (work / "archive-checks.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if args.platform == "macos":
        app_bundle = next((archive / "Products/Applications").glob("*.app"))
        run("codesign", "--verify", "--deep", "--strict", str(app_bundle))


if __name__ == "__main__":
    main()
