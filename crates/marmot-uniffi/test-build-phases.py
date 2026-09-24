#!/usr/bin/env python3
"""Exercise split build orchestration with fake compilers, without an SDK/build.

These tests check phase isolation and assembly inputs; real workflow consumers
remain the authority for generated ABI and platform compatibility.
"""

import hashlib
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
PAGE_POLICY_RUSTC_ARGS = [
    "-C", "link-arg=-Wl,-z,max-page-size=16384",
    "-C", "link-arg=-Wl,-z,common-page-size=16384",
]


def page_policy_args(args):
    return args[args.index("--") + 1:]
SHIM = r'''#!/usr/bin/env python3
import json, os, pathlib, runpy, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
def target_rustflags():
    return {key: os.environ[key] for key in os.environ
        if key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS")}
with open(os.environ["BUILD_TEST_LOG"], "a") as log:
    log.write(json.dumps({"tool": name, "args": args,
        "strip": os.environ.get("CARGO_PROFILE_RELEASE_STRIP"),
        "macos_flags": os.environ.get("CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS"),
        "rustflags": os.environ.get("RUSTFLAGS"),
        "encoded_rustflags": os.environ.get("CARGO_ENCODED_RUSTFLAGS"),
        "target_rustflags": target_rustflags()}) + "\n")
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
            elif suffix == "so" and "--target" in args:
                triple = args[args.index("--target") + 1]
                fixtures = runpy.run_path(os.environ["BUILD_TEST_ANDROID_FIXTURES"])
                if triple in fixtures["TARGET_TO_ABI"]:
                    raw = os.environ.get("BUILD_TEST_ANDROID_ALIGN")
                    align = int(raw) if raw else None
                    path.write_bytes(fixtures["library_for_target"](triple, align))
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
        (self.crate / "marmotkit-release-profile.env").write_text("fixture profile\n")
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
            BUILD_TEST_ANDROID_FIXTURES=str(TOOLS / "test-android-artifact.py"),
            CARGO_TARGET_DIR="target", OTLP_EXPORT="1", PRODUCT_ANALYTICS_EXPORT="1")
        for key in list(self.env):
            if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"}:
                self.env.pop(key)
            elif key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS"):
                self.env.pop(key)
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
        self.assertNotIn("max-page-size", self.log.read_text())
        for path in ["dev/ipf/marmotkit/marmot_uniffi.kt", "dev/ipf/marmotkit/MarmotAndroid.kt", "io/crates/keyring/Keyring.kt"]:
            self.assertTrue((self.crate / "output/android/kotlin" / path).exists())

    def test_native_android_preserves_sibling_abi_and_generated_kotlin(self):
        self.run_phase("kotlin-bindings.sh", "generate")
        self.log.unlink()
        for abi in ["arm64-v8a", "x86_64"]:
            self.run_phase("kotlin-bindings.sh", "native", ANDROID_ABIS=abi)
        cargo = [c for c in self.commands() if c["tool"] == "cargo"]
        self.assertEqual(len(cargo), 2)
        self.assertTrue(all(c["args"][0] == "rustc" and "--lib" in c["args"] and "--target" in c["args"] and c["strip"] == "symbols" for c in cargo))
        for abi in ["arm64-v8a", "x86_64"]:
            self.assertTrue((self.crate / "output/android/jniLibs" / abi / "libmarmot_uniffi.so").exists())
        self.assertTrue((self.crate / "output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt").exists())
        for command in cargo:
            self.assertEqual(page_policy_args(command["args"]), PAGE_POLICY_RUSTC_ARGS)
            self.assertNotIn("max-page-size", json.dumps(command["target_rustflags"]))

    def test_android_page_policy_follows_rustflags_precedence(self):
        self.run_phase("kotlin-bindings.sh", "native", ANDROID_ABIS="armeabi-v7a")
        thirty_two = [c for c in self.commands() if c["tool"] == "cargo"][-1]
        self.assertEqual(thirty_two["args"][0], "build")
        self.assertNotIn("max-page-size", json.dumps(thirty_two))
        self.assertIsNone(thirty_two["rustflags"])
        self.log.unlink()
        self.run_phase("kotlin-bindings.sh", "native", ANDROID_ABIS="arm64-v8a x86",
            RUSTFLAGS="-C debuginfo=0",
            CARGO_BUILD_RUSTFLAGS="-C link-arg=-Wl,-z,origin")
        for command in [c for c in self.commands() if c["tool"] == "cargo"]:
            triple = command["args"][command["args"].index("--target") + 1]
            self.assertEqual(command["rustflags"], "-C debuginfo=0")
            if triple == "aarch64-linux-android":
                self.assertEqual(command["args"][0], "rustc")
                self.assertEqual(page_policy_args(command["args"]), PAGE_POLICY_RUSTC_ARGS)
                self.assertNotIn("max-page-size", json.dumps(command["target_rustflags"]))
                self.assertNotIn("origin", json.dumps(command["target_rustflags"]))
            else:
                self.assertEqual(command["args"][0], "build")
                self.assertNotIn("--", command["args"])
                self.assertNotIn("max-page-size", json.dumps(command))
        self.log.unlink()
        encoded = "-C\x1fdebuginfo=0"
        target_key = "CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS"
        self.run_phase("kotlin-bindings.sh", "native", ANDROID_ABIS="x86_64",
            CARGO_ENCODED_RUSTFLAGS=encoded,
            **{target_key: "-C target-cpu=native"})
        command = [c for c in self.commands() if c["tool"] == "cargo"][-1]
        self.assertEqual(command["encoded_rustflags"], encoded)
        self.assertEqual(command["target_rustflags"][target_key], "-C target-cpu=native")
        self.assertEqual(page_policy_args(command["args"]), PAGE_POLICY_RUSTC_ARGS)
        self.assertEqual(command["rustflags"], None)

    def test_native_android_rejects_misaligned_library_before_success(self):
        result = self.run_phase("kotlin-bindings.sh", "native", success=False,
            ANDROID_ABIS="arm64-v8a", BUILD_TEST_ANDROID_ALIGN="4096")
        self.assertIn("below 16 KB", result.stderr)
        self.assertNotIn("Done.", result.stdout)

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
        fixtures = runpy.run_path(str(TOOLS / "test-android-artifact.py"))
        for part, path in zip(parts, paths):
            if part in {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}:
                align = 0x4000 if part in {"arm64-v8a", "x86_64"} else 0x1000
                library = self.crate / "output/android/jniLibs" / part / "libmarmot_uniffi.so"
                library.parent.mkdir(parents=True, exist_ok=True)
                library.write_bytes(fixtures["elf_with_alignments"](part, [align, align]))
            self.provenance("record", part, path)
        return paths

    def test_android_manifest_uses_observed_build_provenance(self):
        paths = self.record_inputs(["kotlin", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"])
        recorded = json.loads(paths[0].read_text())
        expected_profile_hash = hashlib.sha256(
            (TOOLS / "marmotkit-release-profile.env").read_bytes()
        ).hexdigest()
        self.assertEqual(recorded["release_profile_sha256"], expected_profile_hash)
        self.provenance("verify", "android", "--artifact-root", self.crate / "output/android", *paths)
        native = json.loads(paths[1].read_text())
        library = self.crate / "output/android/jniLibs/arm64-v8a/libmarmot_uniffi.so"
        self.assertEqual(native["library_sha256"], hashlib.sha256(library.read_bytes()).hexdigest())
        self.assertNotIn("library_sha256", json.loads(paths[0].read_text()))
        values = dict(line.split("=", 1) for line in Path(self.env["GITHUB_ENV"]).read_text().splitlines())
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_NDK_HOME"], str(self.root / "ndk"))
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_NDK_VERSION"], "27.2.12479018")
        self.assertEqual(values["MARMOTKIT_BUILD_RUSTC"], "rustc 1.97.1 fixture")
        self.assertEqual(values["MARMOTKIT_BUILD_CARGO"], "cargo 1.97.1 fixture")
        self.assertEqual(values["MARMOTKIT_BUILD_ANDROID_API"], "26")
        Path(self.env["GITHUB_ENV"]).unlink()
        library.write_bytes(library.read_bytes() + b"\x00")
        self.provenance("verify", "android", "--artifact-root", self.crate / "output/android", *paths, success=False)
        self.assertFalse(Path(self.env["GITHUB_ENV"]).exists())

    def test_provenance_rejects_missing_duplicate_and_disagreeing_inputs(self):
        paths = self.record_inputs(["kotlin", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"])
        root = self.crate / "output/android"
        self.provenance("verify", "android", "--artifact-root", root, *paths[:-1], success=False)
        self.provenance("verify", "android", "--artifact-root", root, *paths[:-1], paths[1], success=False)
        original = json.loads(paths[-1].read_text())
        for key in ["source_sha", "builder_sha", "workflow_run_id",
                    "release_profile_sha256", "feature_set", "rustc", "cargo",
                    "android_ndk_home", "android_ndk_version", "android_api", "part",
                    "library_sha256"]:
            with self.subTest(key=key):
                paths[-1].write_text(json.dumps(original | {key: "different"}))
                self.provenance("verify", "android", "--artifact-root", root, *paths, success=False)
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

    def test_snapshot_verification_hashes_the_builder_profile(self):
        workflow = (TOOLS.parents[1] / ".github/workflows/bindings.yaml").read_text()
        verify_steps = workflow.split("      - name: Verify build provenance\n")[1:]
        self.assertEqual(len(verify_steps), 3)
        for step in verify_steps:
            step = step.split("      - name:", 1)[0]
            self.assertNotIn(
                "MARMOTKIT_CRATE_DIR: ${{ github.workspace }}/packaged-source/crates/marmot-uniffi",
                step,
            )

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
