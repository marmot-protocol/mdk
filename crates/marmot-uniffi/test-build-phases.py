#!/usr/bin/env python3
"""Exercise split build orchestration with fake compilers, without an SDK/build.

These tests check phase isolation and assembly inputs; real workflow consumers
remain the authority for generated ABI and platform compatibility.
"""

import json
import os
from pathlib import Path
import shutil
import runpy
import subprocess
import sys
import tempfile
import textwrap
import unittest


TOOLS = Path(__file__).resolve().parent
TARGETS = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "aarch64-apple-darwin"]
ANDROID = ["aarch64-linux-android", "armv7-linux-androideabi", "i686-linux-android", "x86_64-linux-android"]
SHIM = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["BUILD_TEST_LOG"], "a") as log:
    log.write(json.dumps({"tool": name, "args": args,
        "strip": os.environ.get("CARGO_PROFILE_RELEASE_STRIP"),
        "macos_flags": os.environ.get("CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS")}) + "\n")
def put(path, data="fixture"):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
if name == "rustup" and args[:2] == ["target", "list"]:
    print("\n".join(os.environ["BUILD_TEST_TARGETS"].split()))
elif name in ["rustc", "cargo"] and args == ["--version"]:
    print(name + " 1.97.1 fixture")
elif name == "cargo":
    if args[0] == "run":
        out = pathlib.Path(args[args.index("--out-dir") + 1])
        language = args[args.index("--language") + 1]
        if language == "swift":
            for suffix in [".swift", "FFI.h", "FFI.modulemap"]:
                put(out / ("marmot_uniffi" + suffix))
        else:
            put(out / "dev/ipf/marmotkit/marmot_uniffi.kt")
    else:
        root = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if "--target" in args:
            root /= args[args.index("--target") + 1]
        for suffix in ["a", "dylib", "so"]:
            path = root / "release" / ("libmarmot_uniffi." + suffix)
            put(path)
            if suffix == "a":
                path.write_bytes(pathlib.Path(os.environ["BUILD_TEST_ARCHIVE"]).read_bytes())
elif name == "xcodebuild":
    pathlib.Path(args[args.index("-output") + 1]).mkdir(parents=True)
elif name == "llvm-readelf":
    print(".text .dynsym")
elif name == "git":
    if args[0] == "rev-parse":
        print("a" * 40)
    elif args[:2] == ["merge-base", "--is-ancestor"]:
        sys.exit(int(os.environ.get("BUILD_TEST_ANCESTRY_FAILURE", "0")))
'''


class BuildPhases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Assembly now validates real archive structure. Reuse the synthetic
        # native Mach-O fixture instead of feeding the validator plain text.
        fixtures = runpy.run_path(str(TOOLS / "test-release-profile.py"))
        archive = self.root / "native.a"
        fixtures["write_ar"](archive, [("obj.o", fixtures["macho64"](True, b"__TEXT"))])
        self.crate = self.root / "crates/marmot-uniffi"
        self.crate.mkdir(parents=True)
        for folder in ["apple-privacy", "kotlin-support"]:
            shutil.copytree(TOOLS / folder, self.crate / folder)
        self.bin = self.root / ".cargo/bin"
        self.bin.mkdir(parents=True)
        for tool in ["cargo", "rustup", "xcodebuild"]:
            self.shim(self.bin / tool)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, HOME=str(self.root),
            PATH=f"{self.bin}:{os.environ['PATH']}",
            MARMOTKIT_WORKSPACE_DIR=str(self.root), MARMOTKIT_CRATE_DIR=str(self.crate),
            BUILD_TEST_LOG=str(self.log), BUILD_TEST_ARCHIVE=str(archive),
            BUILD_TEST_TARGETS=" ".join(TARGETS + ANDROID),
            CARGO_TARGET_DIR="target", OTLP_EXPORT="1", PRODUCT_ANALYTICS_EXPORT="1")
        ndk = self.root / "ndk"
        for host in ["darwin-x86_64", "linux-x86_64"]:
            for prefix in ["aarch64-linux-android", "armv7a-linux-androideabi", "i686-linux-android", "x86_64-linux-android"]:
                self.shim(ndk / "toolchains/llvm/prebuilt" / host / "bin" / (prefix + "26-clang"))
            self.shim(ndk / "toolchains/llvm/prebuilt" / host / "bin/llvm-readelf")
        self.env["ANDROID_NDK_HOME"] = str(ndk)

    def shim(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(SHIM)
        path.chmod(0o755)

    def run_phase(self, script, *args, success=True, **env):
        result = subprocess.run(["bash", str(TOOLS / script), *args],
            env=self.env | env, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_swift_generation_needs_no_native_target(self):
        self.run_phase("xcframework.sh", "generate")
        commands = self.commands()
        self.assertEqual([c["tool"] for c in commands], ["cargo", "cargo"])
        self.assertTrue(all("--target" not in c["args"] for c in commands))
        self.assertTrue((self.crate / "build/ios/swift/marmot_uniffi.swift").exists())
        self.assertFalse((self.crate / "output").exists())

    def test_ios_assembly_preserves_inputs_and_does_not_compile(self):
        self.run_phase("xcframework.sh", "generate")
        for target in TARGETS[:2]:
            self.run_phase("xcframework.sh", "native", target)
        self.log.unlink()
        self.run_phase("xcframework.sh", "assemble")
        self.assertEqual([c["tool"] for c in self.commands()], ["xcodebuild"])
        self.assertEqual((self.crate / "output/MarmotKit.swift").read_bytes(),
            (self.crate / "build/ios/swift/marmot_uniffi.swift").read_bytes())
        self.assertTrue((self.crate / "output/PrivacyInfo.xcprivacy").exists())

    def test_missing_slice_fails_before_replacing_output(self):
        self.run_phase("xcframework.sh", "generate")
        self.run_phase("xcframework.sh", "native", TARGETS[0])
        output = self.crate / "output/MarmotKit.swift"
        output.parent.mkdir()
        output.write_text("previous bundle")
        self.log.unlink()
        result = self.run_phase("xcframework.sh", "assemble", success=False)
        self.assertIn("missing assembly input", result.stderr)
        self.assertEqual(output.read_text(), "previous bundle")
        self.assertEqual(self.commands(), [])

    def test_macos_uses_shared_swift_and_preserves_deployment_flags(self):
        self.run_phase("xcframework.sh", "generate")
        shutil.copytree(self.crate / "build/ios/swift", self.crate / "build/macos/swift")
        self.run_phase("xcframework-macos.sh", "native")
        native = self.commands()[-1]
        self.assertIn("--target", native["args"])
        self.assertEqual(native["macos_flags"], "-C link-arg=-mmacosx-version-min=15.0 -C embed-bitcode=no")
        self.assertEqual(native["strip"], "none")
        self.log.unlink()
        self.run_phase("xcframework-macos.sh", "assemble")
        self.assertEqual([c["tool"] for c in self.commands()], ["xcodebuild"])
        self.assertTrue((self.crate / "output/macos/MarmotKit.swift").exists())

    def test_kotlin_generation_needs_no_ndk_or_native_targets(self):
        self.run_phase("kotlin-bindings.sh", "generate", ANDROID_NDK_HOME="/missing",
            BUILD_TEST_TARGETS="")
        self.assertEqual([c["tool"] for c in self.commands()], ["cargo", "cargo"])
        self.assertTrue(all(c["strip"] == "none" for c in self.commands()))
        for path in ["dev/ipf/marmotkit/marmot_uniffi.kt", "dev/ipf/marmotkit/MarmotAndroid.kt", "io/crates/keyring/Keyring.kt"]:
            self.assertTrue((self.crate / "output/android/kotlin" / path).exists())

    def test_native_android_preserves_sibling_abi_and_generated_kotlin(self):
        self.run_phase("kotlin-bindings.sh", "generate")
        self.log.unlink()
        for abi in ["arm64-v8a", "x86_64"]:
            self.run_phase("kotlin-bindings.sh", "native", ANDROID_ABIS=abi)
        cargo = [c for c in self.commands() if c["tool"] == "cargo"]
        self.assertEqual(len(cargo), 2)
        self.assertTrue(all(c["args"][0] == "build" and "--target" in c["args"] and c["strip"] == "symbols" for c in cargo))
        for abi in ["arm64-v8a", "x86_64"]:
            self.assertTrue((self.crate / "output/android/jniLibs" / abi / "libmarmot_uniffi.so").exists())
        self.assertTrue((self.crate / "output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt").exists())

    def test_default_commands_still_build_complete_bundles(self):
        for script in ["xcframework.sh", "xcframework-macos.sh", "kotlin-bindings.sh"]:
            self.run_phase(script)
        for path in ["MarmotKit.swift", "macos/MarmotKit.swift", "android/jniLibs/armeabi-v7a/libmarmot_uniffi.so"]:
            self.assertTrue((self.crate / "output" / path).exists())

    def test_invalid_phases_and_targets_do_not_start_builds(self):
        for script, args in [("xcframework.sh", ["native", "bogus"]),
            ("xcframework.sh", ["native"]), ("xcframework.sh", ["generate", "extra"]),
            ("xcframework-macos.sh", ["unknown"]), ("kotlin-bindings.sh", ["unknown"])]:
            self.run_phase(script, *args, success=False)
        self.assertEqual(self.commands(), [])

    def provenance(self, *args, success=True):
        result = subprocess.run([sys.executable, str(TOOLS / "build-provenance.py"), *map(str, args)],
            env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def record_inputs(self, parts):
        for tool in ["git", "rustc"]:
            self.shim(self.bin / tool)
        (self.root / "ndk/source.properties").write_text("Pkg.Revision = 27.2.12479018\n")
        self.env.update(SOURCE_SHA="a" * 40, BUILDER_SHA="b" * 40,
            GITHUB_ENV=str(self.root / "github-env"), GITHUB_RUN_ID="12345")
        paths = [self.root / "provenance" / (part + ".json") for part in parts]
        for part, path in zip(parts, paths):
            self.provenance("record", part, path)
        return paths

    def test_android_manifest_uses_observed_build_provenance(self):
        paths = self.record_inputs(["kotlin", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"])
        self.provenance("verify", "android", *paths)
        values = dict(line.split("=", 1) for line in Path(self.env["GITHUB_ENV"]).read_text().splitlines())
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_NDK_HOME"], str(self.root / "ndk"))
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_NDK_VERSION"], "27.2.12479018")
        self.assertEqual(values["MARMOTKIT_BUILD_RUSTC"], "rustc 1.97.1 fixture")
        self.assertEqual(values["MARMOTKIT_BUILD_CARGO"], "cargo 1.97.1 fixture")
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_API"], "26")

    def test_provenance_rejects_missing_duplicate_and_disagreeing_inputs(self):
        paths = self.record_inputs(["kotlin", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"])
        self.provenance("verify", "android", *paths[:-1], success=False)
        self.provenance("verify", "android", *paths[:-1], paths[1], success=False)
        original = json.loads(paths[-1].read_text())
        for key in ["source_sha", "builder_sha", "workflow_run_id",
                    "release_profile_sha256", "feature_set", "rustc", "cargo",
                    "android_ndk_home", "android_ndk_version", "android_api", "part"]:
            with self.subTest(key=key):
                paths[-1].write_text(json.dumps(original | {key: "different"}))
                self.provenance("verify", "android", *paths, success=False)
        self.assertFalse(Path(self.env["GITHUB_ENV"]).exists())

    def test_apple_provenance_checks_generated_swift_and_native_inputs(self):
        for platform, parts in [("ios", ["swift", "ios-device", "ios-simulator"]),
                                ("macos", ["swift", "macos"])]:
            with self.subTest(platform=platform):
                paths = self.record_inputs(parts)
                self.provenance("verify", platform, *paths)
                data = json.loads(paths[0].read_text())
                paths[0].write_text(json.dumps(data | {"cargo": "different"}))
                self.provenance("verify", platform, *paths, success=False)

    def test_master_cache_warming_rejects_untrusted_source_ancestry(self):
        # Execute the workflow's actual identity script, rather than a copy of
        # its policy. Master-scoped build-only runs must not seed caches using
        # arbitrary branch source, even though branch rehearsals are allowed.
        self.shim(self.bin / "git")
        (self.root / "Cargo.toml").write_text('version = "0.10.3"\n')
        workflow = (TOOLS.parents[1] / ".github/workflows/bindings.yaml").read_text()
        block = workflow.split("      - name: Resolve release identity\n", 1)[1]
        block = block.split("        run: |\n", 1)[1].split("\n  apple-build:", 1)[0]
        script = textwrap.dedent(block)
        cases = [
            ("refs/heads/master", "true", "1", False),
            ("refs/heads/master", "true", "0", True),
            ("refs/heads/master", "false", "1", False),
            ("refs/heads/master", "false", "0", True),
            ("refs/heads/experiment", "true", "1", True),
            ("refs/heads/experiment", "false", "0", False),
        ]
        for ref, build_only, ancestry_failure, success in cases:
            with self.subTest(ref=ref, build_only=build_only, ancestry_failure=ancestry_failure):
                result = subprocess.run(["bash", "-c", script], cwd=self.root,
                    env=self.env | dict(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF=ref,
                        BUILD_ONLY=build_only, REQUESTED_SHA="a" * 40, BUILDER_SHA="b" * 40,
                        GITHUB_OUTPUT=str(self.root / "outputs"),
                        BUILD_TEST_ANCESTRY_FAILURE=ancestry_failure), capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
