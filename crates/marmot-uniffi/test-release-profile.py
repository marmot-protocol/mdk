#!/usr/bin/env python3
"""Release-profile parity, provenance JSON, and builder-control regressions."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


profile_json = load("release_profile_json", HERE / "release-profile-json.py")
archive = load("release_profile_archive", HERE / "release-profile-archive.py")
measure = load("measure_release_profile", HERE / "measure-release-profile.py")

CANONICAL = {
    "opt_level": "3",
    "debug": "0",
    "debug_assertions": False,
    "overflow_checks": False,
    "lto": "thin",
    "codegen_units": 1,
    "panic": "unwind",
    "strip": "none",
}
BASELINE_CONTROL = {"lto": False, "codegen_units": 16}


def env_file_values(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line.startswith("export "):
            continue
        name, _, value = line[len("export ") :].partition("=")
        values[name] = value
    return values


def write_ar(path: Path, members: list[tuple[str, bytes]]) -> None:
    blob = bytearray(b"!<arch>\n")
    for name, content in members:
        encoded = name.encode("ascii")
        if len(encoded) > 15:
            stored = encoded + b"\0"
            content = stored + content
            encoded = f"#1/{len(stored)}".encode()
        header = (
            encoded.ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"644".ljust(8)
            + f"{len(content)}".encode().rjust(10)
            + b"`\n"
        )
        blob.extend(header)
        blob.extend(content)
        if len(content) % 2 == 1:
            blob.append(0)
    path.write_bytes(blob)


def _pack(fmt: str, *values, little: bool) -> bytes:
    endian = "<" if little else ">"
    return struct.pack(endian + fmt, *values)


def macho64(little: bool, segname: bytes, sectname: bytes | None = None) -> bytes:
    """Structurally valid 64-bit Mach-O object with one LC_SEGMENT_64."""
    nsects = 1 if sectname is not None else 0
    cmdsize = 72 + (80 * nsects)
    header = (
        _pack("I", 0xFEEDFACF, little=little)
        + _pack("i", 0x0100000C, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", cmdsize, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    command = (
        _pack("I", 0x19, little=little)
        + _pack("I", cmdsize, little=little)
        + segname.ljust(16, b"\0")
        + _pack("Q", 0, little=little)
        + _pack("Q", 0, little=little)
        + _pack("Q", 0, little=little)
        + _pack("Q", 0, little=little)
        + _pack("i", 0, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", nsects, little=little)
        + _pack("I", 0, little=little)
    )
    if sectname is not None:
        command += (
            sectname.ljust(16, b"\0")
            + segname.ljust(16, b"\0")
            + _pack("Q", 0, little=little)
            + _pack("Q", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
        )
    return header + command


def macho64_mh_object_text_and_llvm(
    little: bool,
    native: bytes,
    bitcode: bytes,
    llvm_sectname: bytes = b"__bitcode",
) -> bytes:
    """MH_OBJECT with __TEXT,__text and a section-level __LLVM leftover."""
    header_size = 32
    nsects = 2
    cmdsize = 72 + 80 * nsects
    text_off = header_size + cmdsize
    bitcode_off = text_off + len(native)
    total = bitcode_off + len(bitcode)

    def section(sectname: bytes, segname: bytes, addr: int, size: int, offset: int) -> bytes:
        return (
            sectname.ljust(16, b"\0")
            + segname.ljust(16, b"\0")
            + _pack("Q", addr, little=little)
            + _pack("Q", size, little=little)
            + _pack("I", offset, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
        )

    header = (
        _pack("I", 0xFEEDFACF, little=little)
        + _pack("i", 0x0100000C, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", cmdsize, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    command = (
        _pack("I", 0x19, little=little)
        + _pack("I", cmdsize, little=little)
        + b"__TEXT".ljust(16, b"\0")
        + _pack("Q", 0, little=little)
        + _pack("Q", total, little=little)
        + _pack("Q", 0, little=little)
        + _pack("Q", total, little=little)
        + _pack("i", 7, little=little)
        + _pack("i", 7, little=little)
        + _pack("I", nsects, little=little)
        + _pack("I", 0, little=little)
        + section(b"__text", b"__TEXT", 0, len(native), text_off)
        + section(llvm_sectname, b"__LLVM", len(native), len(bitcode), bitcode_off)
    )
    return header + command + native + bitcode


def macho32(little: bool, segname: bytes) -> bytes:
    header = (
        _pack("I", 0xFEEDFACE, little=little)
        + _pack("i", 7, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", 56, little=little)
        + _pack("I", 0, little=little)
    )
    command = (
        _pack("I", 0x01, little=little)
        + _pack("I", 56, little=little)
        + segname.ljust(16, b"\0")
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
        + _pack("i", 0, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    return header + command


def write_criterion_estimates(root: Path, point_estimate: float) -> Path:
    estimates = (
        root
        / "criterion"
        / "create_group"
        / "1 invitees, retention disabled"
        / "new"
        / "estimates.json"
    )
    estimates.parent.mkdir(parents=True, exist_ok=True)
    estimates.write_text(
        json.dumps(
            {
                "mean": {
                    "point_estimate": point_estimate,
                    "confidence_interval": {
                        "lower_bound": point_estimate - 1,
                        "upper_bound": point_estimate + 1,
                    },
                }
            }
        )
    )
    return estimates


def write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class ReleaseProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # These fixtures deliberately contain synthetic, non-linkable objects.
        # Real toolchain reconstruction/link checks live in test-native-archive.py.
        self.writer = patch.object(archive, "write_archive", side_effect=write_ar)
        self.writer.start()
        self.addCleanup(self.writer.stop)
        inspect = archive.inspect_otool
        self.inspector = patch.object(archive, "inspect_otool", side_effect=lambda path, text=None: inspect(path, text) if text is not None else None)
        self.inspector.start()
        self.addCleanup(self.inspector.stop)

    def test_root_and_canonical_thin_parity(self):
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
        release = cargo["profile"]["release"]
        self.assertEqual(release["lto"], "thin")
        self.assertEqual(release["codegen-units"], 1)
        self.assertEqual(release["strip"], "none")
        self.assertNotIn("panic", release)
        env = env_file_values(HERE / "marmotkit-release-profile.env")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_LTO"], "thin")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "1")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_STRIP"], "none")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_DEBUG"], "0")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_PANIC"], "unwind")
        self.assertEqual(profile_json.profile_from_env(env), CANONICAL)
        self.assertNotEqual(CANONICAL["lto"], BASELINE_CONTROL["lto"])
        self.assertNotEqual(CANONICAL["codegen_units"], BASELINE_CONTROL["codegen_units"])

    def test_standard_release_path_and_symbol_policy(self):
        cargo = (ROOT / "Cargo.toml").read_text()
        self.assertNotIn("[profile.release-size]", cargo)
        self.assertNotIn("lto = \"fat\"", cargo)
        env_text = (HERE / "marmotkit-release-profile.env").read_text()
        self.assertIn("strip=none", env_text)
        self.assertIn("Android target builds", env_text)
        for script in ("kotlin-bindings.sh", "xcframework.sh", "xcframework-macos.sh"):
            text = (HERE / script).read_text()
            self.assertIn('source "$TOOL_DIR/marmotkit-release-profile.env"', text)
        kotlin = (HERE / "kotlin-bindings.sh").read_text()
        self.assertIn("CARGO_PROFILE_RELEASE_STRIP=symbols", kotlin)
        self.assertIn("host dylib must keep its symbol table", kotlin)
        apple = (HERE / "xcframework.sh").read_text() + (HERE / "xcframework-macos.sh").read_text()
        self.assertNotIn("CARGO_PROFILE_RELEASE_STRIP=symbols", apple)
        self.assertIn("embed-bitcode=no", apple)
        self.assertIn("release-profile-archive.py\" --sanitize", apple)
        self.assertNotIn("whitelist", apple.lower())
        self.assertIn("Do not skip", apple)

    def test_serializers_type_false_and_thin_lto(self):
        env = env_file_values(HERE / "marmotkit-release-profile.env")
        thin = profile_json.profile_from_env(env)
        self.assertEqual(thin["lto"], "thin")
        self.assertIsInstance(thin["codegen_units"], int)
        control = dict(env)
        control["CARGO_PROFILE_RELEASE_LTO"] = "false"
        control["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] = "16"
        parsed = profile_json.profile_from_env(control)
        self.assertIs(parsed["lto"], False)
        self.assertEqual(parsed["codegen_units"], 16)
        self.assertEqual(parsed["strip"], "none")
        self.assertEqual(parsed["panic"], "unwind")
        encoded = json.loads(profile_json.profile_json(control))
        self.assertIs(encoded["lto"], False)

    def test_serializers_reject_unknown_and_malformed_values(self):
        env = env_file_values(HERE / "marmotkit-release-profile.env")
        for name, value in [
            ("CARGO_PROFILE_RELEASE_LTO", "thin\n, \"oops\""),
            ("CARGO_PROFILE_RELEASE_LTO", "full"),
            ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1; rm -rf /"),
            ("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "FALSE"),
            ("CARGO_PROFILE_RELEASE_STRIP", ""),
        ]:
            bad = dict(env)
            bad[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(profile_json.ProfileError):
                profile_json.profile_from_env(bad)
        missing = dict(env)
        del missing["CARGO_PROFILE_RELEASE_LTO"]
        with self.assertRaises(profile_json.ProfileError):
            profile_json.profile_from_env(missing)

    def test_package_scripts_use_shared_serializer(self):
        for name in ("package-ios-artifacts.sh", "package-macos-artifacts.sh"):
            text = (HERE / name).read_text()
            self.assertIn("release-profile-json.py", text)
            self.assertNotIn("lto\": $CARGO_PROFILE_RELEASE_LTO", text)

    def test_archive_rejects_bitcode_and_keeps_duplicate_names(self):
        native = self.root / "native.a"
        bitcode = self.root / "bitcode.a"
        mixed = self.root / "mixed.a"
        write_ar(native, [("obj.o", b"\xcf\xfa\xed\xfe" + b"native-object")])
        write_ar(bitcode, [("obj.o", archive.LLVM_BITCODE_MAGIC + b"ir")])
        write_ar(
            mixed,
            [
                ("dup.o", b"\xcf\xfa\xed\xfe" + b"first"),
                ("dup.o", archive.LLVM_WRAPPER_MAGIC + b"second"),
            ],
        )
        self.assertGreater(archive.check_archive(native), 0)
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(bitcode)
        with self.assertRaisesRegex(archive.ArchiveError, "member 1"):
            archive.check_archive(mixed)
        otool = "Archive : mixed.a(dup.o)\n  sectname __bitcode\n  segname __LLVM\n"
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(native, otool)

    def test_macho_byte_level_detects_llvm_for_both_endians(self):
        short_native = b"\xcf\xfa\xed\xfe" + b"native-object"
        self.assertFalse(archive.member_has_bitcode(short_native))
        for little in (True, False):
            with self.subTest(little=little):
                native = macho64(little, b"__TEXT")
                llvm = macho64(little, b"__LLVM")
                bitcode_section = macho64(little, b"__TEXT", sectname=b"__bitcode")
                llvm_bundle = macho64_mh_object_text_and_llvm(
                    little, b"TEXT", b"B" * 0x80, llvm_sectname=b"__bundle"
                )
                native32 = macho32(little, b"__TEXT")
                llvm32 = macho32(little, b"__LLVM")
                self.assertFalse(archive.member_has_bitcode(native))
                self.assertFalse(archive.member_has_bitcode(native32))
                self.assertTrue(archive.member_has_bitcode(llvm))
                self.assertTrue(archive.member_has_bitcode(bitcode_section))
                self.assertTrue(archive.member_has_bitcode(llvm_bundle))
                self.assertTrue(archive.member_has_bitcode(llvm32))
                accepted = self.root / f"native-{'le' if little else 'be'}.a"
                rejected = self.root / f"llvm-{'le' if little else 'be'}.a"
                write_ar(accepted, [("obj.o", native)])
                write_ar(rejected, [("obj.o", llvm)])
                self.assertGreater(archive.check_archive(accepted), 0)
                with self.assertRaises(archive.ArchiveError):
                    archive.check_archive(rejected)

    def test_bsd_long_name_length_uses_archive_error(self):
        header = (
            b"#1/xx".ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"644".ljust(8)
            + b"4".rjust(10)
            + b"`\n"
            + b"name"
        )
        with self.assertRaisesRegex(archive.ArchiveError, "invalid BSD long name length"):
            list(archive.iter_ar_members(b"!<arch>\n" + header))

    def test_sanitize_does_not_whitelist_raw_bitcode_members(self):
        path = self.root / "raw-bitcode.a"
        archive.write_archive(
            path,
            [
                (
                    "compiler_builtins-c474715e2ac50578.rcgu.o",
                    archive.LLVM_BITCODE_MAGIC + b"ir",
                )
            ],
        )
        with self.assertRaisesRegex(archive.ArchiveError, "raw LLVM bitcode"):
            archive.sanitize_archive(path)
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(path)

    def test_measurement_applies_apple_embed_bitcode_flag(self):
        env = measure.apply_apple_native_archive_rustflags(
            {"CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS": "-C link-arg=-something"},
            "aarch64-apple-ios",
        )
        self.assertIn("embed-bitcode=no", env["CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS"])
        self.assertIn("link-arg=-something", env["CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS"])

    def test_clang_llvm_bitcode_archive_rejected_without_otool(self):
        clang = shutil.which("clang")
        if not clang:
            self.skipTest("clang unavailable")
        src = self.root / "probe.c"
        src.write_text("int marmotkit_bitcode_probe(void) { return 1; }\n")
        obj = self.root / "probe.o"
        completed = subprocess.run(
            [clang, "-c", "-emit-llvm", "-o", str(obj), str(src)],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or not obj.exists():
            self.skipTest(completed.stderr or "clang -emit-llvm unavailable")
        archive_path = self.root / "clang-bitcode.a"
        write_ar(archive_path, [("probe.o", obj.read_bytes())])
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(archive_path)

    def test_builders_keep_android_strip_isolated(self):
        log = self.root / "cargo.jsonl"
        log.write_text("")
        bin_dir = self.root / "bin"
        target = self.root / "target"
        write_executable(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
        workspace = self.root / "old-source"
        crate = workspace / "crates/marmot-uniffi"
        (crate / "kotlin-support/dev/ipf/marmotkit").mkdir(parents=True)
        (crate / "kotlin-support/dev/ipf/marmotkit/MarmotAndroid.kt").write_text("class MarmotAndroid\n")
        (crate / "kotlin-support/io/crates/keyring").mkdir(parents=True)
        (crate / "kotlin-support/io/crates/keyring/Keyring.kt").write_text("class Keyring\n")
        (crate / "marmotkit-release-profile.env").write_text(
            "export CARGO_PROFILE_RELEASE_LTO=false\n"
            "export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16\n"
            "export CARGO_PROFILE_RELEASE_STRIP=none\n"
        )
        write_executable(
            bin_dir / "rustup",
            "#!/bin/sh\n"
            "if [ \"$1\" = target ] && [ \"$2\" = list ]; then\n"
            "  printf '%s\\n' aarch64-linux-android armv7-linux-androideabi "
            "i686-linux-android x86_64-linux-android\n"
            "fi\n",
        )
        write_executable(
            bin_dir / "cargo",
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            f"log = Path({str(log)!r})\n"
            "entry = {'argv': sys.argv[1:], 'strip': os.environ.get('CARGO_PROFILE_RELEASE_STRIP'),"
            " 'lto': os.environ.get('CARGO_PROFILE_RELEASE_LTO'),"
            " 'codegen': os.environ.get('CARGO_PROFILE_RELEASE_CODEGEN_UNITS'),"
            " 'rustflags': os.environ.get('RUSTFLAGS'),"
            " 'encoded_rustflags': os.environ.get('CARGO_ENCODED_RUSTFLAGS'),"
            " 'target_rustflags': {k: os.environ[k] for k in os.environ if k.startswith('CARGO_TARGET_') and k.endswith('_RUSTFLAGS')}}\n"
            "with log.open('a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps(entry) + '\\n')\n"
            "args = sys.argv[1:]\n"
            "target_dir = Path(os.environ['CARGO_TARGET_DIR'])\n"
            "if args and args[0] in {'build', 'rustc'}:\n"
            "    triple = None\n"
            "    if '--target' in args:\n"
            "        triple = args[args.index('--target') + 1]\n"
            "    if triple:\n"
            "        out = target_dir / triple / 'release' / 'libmarmot_uniffi.so'\n"
            "    else:\n"
            "        out = target_dir / 'release' / 'libmarmot_uniffi.so'\n"
            "    out.parent.mkdir(parents=True, exist_ok=True)\n"
            "    if triple:\n"
            "        out.write_bytes(Path(os.environ['ANDROID_ELF_DIR'], triple).read_bytes())\n"
            "    else:\n"
            "        out.write_bytes(b'library')\n"
            "elif args and args[0] == 'run':\n"
            "    out_dir = Path(args[args.index('--out-dir') + 1])\n"
            "    generated = out_dir / 'dev/ipf/marmotkit/marmot_uniffi.kt'\n"
            "    generated.parent.mkdir(parents=True, exist_ok=True)\n"
            "    generated.write_text('generated')\n"
            "else:\n"
            "    raise SystemExit('unexpected cargo invocation')\n",
        )
        ndk = self.root / "ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
        for name in (
            "aarch64-linux-android26-clang",
            "armv7a-linux-androideabi26-clang",
            "i686-linux-android26-clang",
            "x86_64-linux-android26-clang",
            "llvm-ar",
            "llvm-ranlib",
        ):
            write_executable(ndk / name, "#!/bin/sh\nexit 0\n")
        write_executable(
            ndk / "llvm-readelf",
            "#!/bin/sh\necho 'There are 4 section headers'\n",
        )
        android_fixtures = load("android_artifact_fixtures", HERE / "test-android-artifact.py")
        elf_dir = self.root / "android-elf"
        elf_dir.mkdir()
        for triple, abi in android_fixtures.TARGET_TO_ABI.items():
            align = 0x4000 if abi in android_fixtures.SIXTY_FOUR else 0x1000
            (elf_dir / triple).write_bytes(android_fixtures.elf_with_alignments(abi, [align, align]))
        env = os.environ.copy()
        for key in list(env):
            if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"}:
                env.pop(key)
            elif key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS"):
                env.pop(key)
        env["HOME"] = str(self.root / "home-kotlin")
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["ANDROID_NDK_HOME"] = str(self.root / "ndk")
        env["ANDROID_ELF_DIR"] = str(elf_dir)
        env["CARGO_TARGET_DIR"] = str(target)
        env["MARMOTKIT_WORKSPACE_DIR"] = str(workspace)
        env["MARMOTKIT_CRATE_DIR"] = str(crate)
        env["OTLP_EXPORT"] = "1"
        env["PRODUCT_ANALYTICS_EXPORT"] = "1"
        subprocess.run(
            [str(HERE / "kotlin-bindings.sh")],
            check=True,
            env=env,
            cwd=ROOT,
        )
        records = [json.loads(line) for line in log.read_text().splitlines() if line]
        host = [row for row in records if row["argv"][:1] == ["build"] and "--target" not in row["argv"]]
        android = [row for row in records if "--target" in row["argv"]]
        generate = [row for row in records if row["argv"][:1] == ["run"]]
        self.assertEqual(len(host), 1)
        self.assertEqual(host[0]["strip"], "none")
        self.assertEqual(host[0]["lto"], "thin")
        self.assertEqual(host[0]["codegen"], "1")
        self.assertEqual(len(android), 4)
        for row in android:
            self.assertEqual(row["strip"], "symbols")
            self.assertEqual(row["lto"], "thin")
            self.assertEqual(row["codegen"], "1")
        self.assertEqual(len(generate), 1)
        self.assertNotIn("max-page-size", json.dumps(host[0]["target_rustflags"]))
        self.assertFalse(host[0]["rustflags"])
        for row in android:
            triple = row["argv"][row["argv"].index("--target") + 1]
            if triple in {"aarch64-linux-android", "x86_64-linux-android"}:
                self.assertEqual(row["argv"][0], "rustc")
                split = row["argv"].index("--")
                self.assertEqual(row["argv"][split + 1:], [
                    "-C", "link-arg=-Wl,-z,max-page-size=16384",
                    "-C", "link-arg=-Wl,-z,common-page-size=16384",
                ])
                self.assertNotIn("max-page-size", json.dumps(row["target_rustflags"]))
            else:
                self.assertEqual(row["argv"][0], "build")
                self.assertNotIn("max-page-size", json.dumps(row))
                self.assertFalse(row["rustflags"])
        self.assertTrue((crate / "output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt").is_file())

    def test_kotlin_generation_is_required(self):
        log = self.root / "cargo.jsonl"
        log.write_text("")
        bin_dir = self.root / "bin"
        workspace = self.root / "old-source"
        write_executable(bin_dir / "uname", "#!/bin/sh\necho Linux\n")
        crate = workspace / "crates/marmot-uniffi"
        (crate / "kotlin-support/dev/ipf/marmotkit").mkdir(parents=True)
        (crate / "kotlin-support/io/crates/keyring").mkdir(parents=True)
        write_executable(
            bin_dir / "rustup",
            "#!/bin/sh\nprintf '%s\\n' aarch64-linux-android armv7-linux-androideabi "
            "i686-linux-android x86_64-linux-android\n",
        )
        write_executable(
            bin_dir / "cargo",
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "target_dir = Path(os.environ['CARGO_TARGET_DIR'])\n"
            "if args and args[0] == 'build' and '--target' not in args:\n"
            "    out = target_dir / 'release' / 'libmarmot_uniffi.so'\n"
            "    out.parent.mkdir(parents=True, exist_ok=True)\n"
            "    out.write_bytes(b'library')\n"
            "elif args and args[0] == 'run':\n"
            "    raise SystemExit(0)\n"
            "else:\n"
            "    raise SystemExit('unexpected cargo invocation')\n",
        )
        ndk = self.root / "ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
        ndk.mkdir(parents=True)
        env = os.environ.copy()
        env["HOME"] = str(self.root / "home-kotlin-required")
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["ANDROID_NDK_HOME"] = str(self.root / "ndk")
        env["CARGO_TARGET_DIR"] = str(self.root / "target")
        env["MARMOTKIT_WORKSPACE_DIR"] = str(workspace)
        env["MARMOTKIT_CRATE_DIR"] = str(crate)
        completed = subprocess.run(
            [str(HERE / "kotlin-bindings.sh")],
            env=env,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("produced no Kotlin binding", completed.stderr)

    def test_apple_builders_keep_symbols_and_builder_owned_profile(self):
        for script, extras in (
            (
                "xcframework.sh",
                {
                    "targets": ["aarch64-apple-ios", "aarch64-apple-ios-sim"],
                    "output": "output/MarmotKit.xcframework",
                },
            ),
            (
                "xcframework-macos.sh",
                {
                    "targets": ["aarch64-apple-darwin"],
                    "output": "output/macos/MarmotKit.xcframework",
                },
            ),
        ):
            with self.subTest(script=script):
                self._assert_apple_builder_profile(script, extras)

    def _assert_apple_builder_profile(self, script: str, extras: dict):
        log = self.root / f"{script}.jsonl"
        log.write_text("")
        bin_dir = self.root / f"bin-{script}"
        workspace = self.root / f"old-source-{script}"
        crate = workspace / "crates/marmot-uniffi"
        privacy = crate / "apple-privacy"
        shutil.copytree(HERE / "apple-privacy", privacy)
        (crate / "marmotkit-release-profile.env").write_text(
            "export CARGO_PROFILE_RELEASE_LTO=false\n"
            "export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16\n"
            "export CARGO_PROFILE_RELEASE_STRIP=none\n"
        )
        write_executable(
            bin_dir / "rustup",
            "#!/bin/sh\nexit 0\n",
        )
        write_executable(
            bin_dir / "xcodebuild",
            "#!/bin/sh\n"
            "out=''\n"
            "while [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = -output ]; then out=$2; fi\n"
            "  shift\n"
            "done\n"
            "mkdir -p \"$out\"\n"
            "printf 'xcframework' > \"$out/Info.plist\"\n",
        )
        native = macho64(True, b"__TEXT")
        write_ar(self.root / f"{script}-native.a", [("obj.o", native)])
        write_executable(
            bin_dir / "cargo",
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            f"log = Path({str(log)!r})\n"
            f"native = Path({str(self.root / (script + '-native.a'))!r}).read_bytes()\n"
            "entry = {'argv': sys.argv[1:], 'strip': os.environ.get('CARGO_PROFILE_RELEASE_STRIP'),"
            " 'lto': os.environ.get('CARGO_PROFILE_RELEASE_LTO'),"
            " 'codegen': os.environ.get('CARGO_PROFILE_RELEASE_CODEGEN_UNITS'),"
            " 'ios_rustflags': os.environ.get('CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS'),"
            " 'ios_sim_rustflags': os.environ.get('CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS'),"
            " 'darwin_rustflags': os.environ.get('CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS')}\n"
            "with log.open('a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps(entry) + '\\n')\n"
            "args = sys.argv[1:]\n"
            f"workspace = Path({str(workspace)!r})\n"
            "target_dir = workspace / 'target'\n"
            "if args and args[0] == 'build':\n"
            "    triple = args[args.index('--target') + 1] if '--target' in args else None\n"
            "    if triple:\n"
            "        out = target_dir / triple / 'release' / 'libmarmot_uniffi.a'\n"
            "    else:\n"
            "        out = target_dir / 'release' / 'libmarmot_uniffi.dylib'\n"
            "    out.parent.mkdir(parents=True, exist_ok=True)\n"
            "    out.write_bytes(native if triple else b'host')\n"
            "elif args and args[0] == 'run':\n"
            "    out_dir = Path(args[args.index('--out-dir') + 1])\n"
            "    out_dir.mkdir(parents=True, exist_ok=True)\n"
            "    (out_dir / 'marmot_uniffi.swift').write_text('swift')\n"
            "    (out_dir / 'marmot_uniffiFFI.h').write_text('header')\n"
            "    (out_dir / 'marmot_uniffiFFI.modulemap').write_text('module')\n"
            "else:\n"
            "    raise SystemExit('unexpected cargo invocation')\n",
        )
        env = os.environ.copy()
        env["HOME"] = str(self.root / f"home-{script}")
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["MARMOTKIT_WORKSPACE_DIR"] = str(workspace)
        env["MARMOTKIT_CRATE_DIR"] = str(crate)
        env["OTLP_EXPORT"] = "1"
        env["PRODUCT_ANALYTICS_EXPORT"] = "1"
        subprocess.run([str(HERE / script)], check=True, env=env, cwd=ROOT)
        records = [json.loads(line) for line in log.read_text().splitlines() if line]
        builds = [row for row in records if row["argv"][:1] == ["build"]]
        generate = [row for row in records if row["argv"][:1] == ["run"]]
        self.assertGreaterEqual(len(builds), 1 + len(extras["targets"]))
        for row in records:
            self.assertEqual(row["strip"], "none")
            self.assertEqual(row["lto"], "thin")
            self.assertEqual(row["codegen"], "1")
            self.assertNotIn("CARGO_PROFILE_RELEASE_STRIP=symbols", " ".join(row["argv"]))
        target_builds = [row for row in builds if "--target" in row["argv"]]
        self.assertEqual(len(target_builds), len(extras["targets"]))
        for row in target_builds:
            triple = row["argv"][row["argv"].index("--target") + 1]
            if triple == "aarch64-apple-ios":
                self.assertIn("embed-bitcode=no", row["ios_rustflags"] or "")
            elif triple == "aarch64-apple-ios-sim":
                self.assertIn("embed-bitcode=no", row["ios_sim_rustflags"] or "")
            elif triple == "aarch64-apple-darwin":
                self.assertIn("embed-bitcode=no", row["darwin_rustflags"] or "")
                self.assertIn("link-arg=-mmacosx-version-min=", row["darwin_rustflags"] or "")
        self.assertEqual(len(generate), 1)
        # On Apple Silicon the host and distribution target share a triple.
        # Cargo applies target rustflags even without --target, so exporting
        # embed-bitcode=no globally breaks the thin-LTO bindgen executable.
        host_commands = [row for row in records if "--target" not in row["argv"]]
        for row in host_commands:
            self.assertNotIn("embed-bitcode=no", row["darwin_rustflags"] or "")
        self.assertTrue((crate / extras["output"]).exists())

    def test_automatic_profile_workflow_only_validates_candidate_packages(self):
        text = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        self.assertIn("pull_request:", text)
        self.assertNotIn("measure-release-profile.py", text)
        self.assertNotIn("release-profile-measurements", text)
        self.assertIn("./crates/marmot-uniffi/kotlin-bindings.sh generate", text)
        for invocation in (
            "ANDROID_ABIS=\"$PART\" ./crates/marmot-uniffi/kotlin-bindings.sh native",
            "./crates/marmot-uniffi/xcframework.sh native aarch64-apple-ios ;;",
            "./crates/marmot-uniffi/xcframework.sh native aarch64-apple-ios-sim ;;",
            "./crates/marmot-uniffi/xcframework-macos.sh native ;;",
            "./crates/marmot-uniffi/xcframework.sh assemble",
            "./crates/marmot-uniffi/xcframework-macos.sh assemble",
        ):
            self.assertEqual(text.count(invocation), 1, invocation)

    def test_automatic_profile_workflow_binds_same_run_inputs_to_exact_head(self):
        text = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        self.assertIn("github.event.pull_request.number || github.ref", text)
        self.assertNotIn("group: marmotkit-profile-${{ github.event.pull_request.head.sha", text)
        self.assertIn("github.event.pull_request.head.sha || github.sha", text)
        self.assertIn("actions/download-artifact@", text)
        self.assertIn("build-provenance.py verify android", text)
        self.assertIn("build-provenance.py verify ios", text)
        self.assertIn("build-provenance.py verify macos", text)
        self.assertIn("GITHUB_RUN_ID: ${{ github.run_id }}", text)
        self.assertNotIn("run-id:", text)
        self.assertGreaterEqual(text.count("MARMOTKIT_WORKSPACE_DIR: ${{ github.workspace }}"), 2)

    def test_automatic_profile_workflow_limits_cost_and_preserves_diagnostics(self):
        text = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        trigger = text.split("permissions:", 1)[0]
        excluded = [
            line.strip().removeprefix("- ").strip('"').strip("'")
            for line in trigger.splitlines()
            if line.strip().startswith(("- \"!crates/marmot-uniffi/", "- '!crates/marmot-uniffi/"))
        ]

        def github_glob_matches(path, pattern):
            expression = ""
            index = 0
            while index < len(pattern):
                if pattern.startswith("**", index):
                    expression += ".*"
                    index += 2
                elif pattern[index] == "*":
                    expression += "[^/]*"
                    index += 1
                else:
                    expression += re.escape(pattern[index])
                    index += 1
            return re.fullmatch(expression, path) is not None

        for document in HERE.rglob("*.md"):
            relative = document.relative_to(ROOT).as_posix()
            self.assertTrue(
                any(github_glob_matches(relative, pattern.removeprefix("!")) for pattern in excluded),
                f"Markdown-only change would still trigger packaging: {relative}",
            )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", text)
        self.assertGreaterEqual(text.count("error: sdkmanager not found under $sdk_root"), 1)
        apple_build = text.split("  apple-build:", 1)[1].split("  android-build:", 1)[0]
        self.assertIn("if: matrix.part == 'swift'", apple_build)
        self.assertIn("rustup component add llvm-tools-preview", apple_build)
        self.assertIn("python3 crates/marmot-uniffi/test-native-archive.py", apple_build)
        ios_package = text.split("  ios-package:", 1)[1]
        self.assertNotIn("test-native-archive.py", ios_package)

    def test_profile_workflows_are_non_publishing_and_diagnostic_rich(self):
        for workflow in ("bindings-profile.yml", "bindings-profile-measurement.yml"):
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertIn("persist-credentials: false", text)
                self.assertIn("contents: read", text)
                self.assertNotIn("pull_request_target", text)
                self.assertNotIn("secrets.", text)
                self.assertNotIn("softprops/action-gh-release", text)
                self.assertNotIn("upload-to-github-release", text)
                self.assertGreaterEqual(text.count("if: always()"), 2)
                self.assertIn("xcodebuild -version", text)

    def test_comparative_measurement_is_manual_and_complete(self):
        text = (ROOT / ".github/workflows/bindings-profile-measurement.yml").read_text()
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn("source_sha:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertIn("--host --android --cpu", text)
        self.assertIn("--apple", text)
        self.assertGreaterEqual(text.count("--source-sha \"$SOURCE_SHA\""), 2)
        self.assertGreaterEqual(text.count("--builder-sha \"$SOURCE_SHA\""), 2)
        self.assertIn("cpu-${variant}/criterion", text)
        self.assertIn("target/release-profile-measure/logs", text)
        self.assertNotIn("Swatinem/rust-cache", text)

    def test_profile_cache_writes_are_trusted_only(self):
        automatic = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        measurement = (ROOT / ".github/workflows/bindings-profile-measurement.yml").read_text()
        trusted = "save-if: ${{ github.event_name != 'pull_request' && github.ref == 'refs/heads/master' }}"
        self.assertGreaterEqual(automatic.count(trusted), 2)
        self.assertNotIn("save-if: true", automatic)
        self.assertNotIn("save-if: true", measurement)
        self.assertNotIn("save-if:", measurement)

    def test_measurement_policy_requires_explicit_evidence_for_policy_changes(self):
        guidance = (HERE / "AGENTS.md").read_text()
        self.assertIn(
            "must dispatch and link completed comparative evidence before merge",
            " ".join(guidance.split()),
        )

    def test_measurement_stage_identifies_unsanitized_apple_archives(self):
        baseline = self.root / "baseline.a"
        candidate = self.root / "candidate.a"
        baseline.write_bytes(b"baseline")
        candidate.write_bytes(b"candidate")
        for triple in measure.APPLE_SLICES:
            with self.subTest(target=triple):
                row = measure.artifact_row(
                    triple, "apple_static_archive", "none", baseline, candidate
                )
                self.assertEqual(row["measurement_stage"], "pre-sanitization Cargo archive")
                self.assertEqual(row["candidate_sha256"], measure.sha256_file(candidate))
                markdown = measure.render_markdown({
                    "schema_version": 1,
                    "source_sha": "a" * 40,
                    "builder_sha": "b" * 40,
                    "artifacts": [row],
                    "cpu_runs": [],
                })
                self.assertIn("| Measurement stage |", markdown)
                self.assertIn("| pre-sanitization Cargo archive |", markdown)
        android = measure.artifact_row(
            "aarch64-linux-android", "android_jni_so", "symbols", baseline, candidate
        )
        self.assertEqual(android["measurement_stage"], "Cargo build output")
        missing = measure.artifact_row(
            "aarch64-apple-ios", "apple_static_archive", "none", None, None
        )
        self.assertEqual(missing["measurement_stage"], "pre-sanitization Cargo archive")
        self.assertEqual(missing["availability"], "unavailable")

    def test_unavailable_measurements_are_not_zero(self):
        row = measure.artifact_row(
            "aarch64-linux-android",
            "android_jni_so",
            "symbols",
            None,
            None,
            "Android NDK or Rust target unavailable",
        )
        self.assertIsNone(row["baseline_bytes"])
        self.assertIsNone(row["candidate_bytes"])
        self.assertIsNone(row["delta_bytes"])
        self.assertEqual(row["availability"], "unavailable")
        self.assertNotEqual(row["baseline_bytes"], 0)
        self.assertNotEqual(row["candidate_bytes"], 0)

    def test_missing_artifact_paths_are_unavailable(self):
        missing = self.root / "missing.so"
        row = measure.artifact_row(
            "host",
            "host_generation_library",
            "none",
            missing,
            missing,
        )
        self.assertEqual(row["availability"], "unavailable")
        self.assertEqual(row["reason"], "artifact files missing")
        self.assertIsNone(row["baseline_bytes"])
        self.assertIsNone(row["candidate_bytes"])

    def test_android_reduction_gate_requires_measured_shrink(self):
        missing = [
            {
                "target": "aarch64-linux-android",
                "availability": "unavailable",
                "reason": "Android NDK or Rust target unavailable",
            }
        ]
        self.assertTrue(measure.android_reduction_failures(missing))
        grown = [
            {
                "target": "aarch64-linux-android",
                "availability": "measured",
                "baseline_bytes": 10,
                "candidate_bytes": 12,
                "delta_bytes": 2,
            },
            {
                "target": "armv7-linux-androideabi",
                "availability": "measured",
                "baseline_bytes": 8,
                "candidate_bytes": 7,
                "delta_bytes": -1,
            },
        ]
        failures = measure.android_reduction_failures(grown)
        self.assertEqual(len(failures), 1)
        self.assertIn("aarch64-linux-android", failures[0])
        shrunk = [
            {
                "target": "aarch64-linux-android",
                "availability": "measured",
                "baseline_bytes": 10,
                "candidate_bytes": 8,
                "delta_bytes": -2,
            },
            {
                "target": "armv7-linux-androideabi",
                "availability": "measured",
                "baseline_bytes": 8,
                "candidate_bytes": 7,
                "delta_bytes": -1,
            },
            {
                "target": "x86_64-linux-android",
                "availability": "measured",
                "baseline_bytes": 9,
                "candidate_bytes": 11,
                "delta_bytes": 2,
            },
        ]
        self.assertEqual(measure.android_reduction_failures(shrunk), [])

    def test_measurement_overrides_only_lto_and_codegen(self):
        base = {"PATH": "/bin"}
        env = measure.profile_env(base, "baseline", "symbols")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_LTO"], "false")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "16")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_STRIP"], "symbols")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_OPT_LEVEL"], "3")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_DEBUG"], "0")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_PANIC"], "unwind")
        candidate = measure.profile_env(base, "candidate", "none")
        self.assertEqual(candidate["CARGO_PROFILE_RELEASE_LTO"], "thin")
        self.assertEqual(candidate["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "1")
        self.assertEqual(candidate["CARGO_PROFILE_RELEASE_STRIP"], "none")

    def test_committed_measurements_are_schema_one(self):
        report = json.loads((HERE / "release-profile-measurements.json").read_text())
        self.assertEqual(report["schema_version"], 1)
        self.assertRegex(report["source_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(report["builder_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(report["lock_sha256"], r"^[0-9a-f]{64}$")
        host = next(
            row
            for row in report["artifacts"]
            if row["kind"] == "host_generation_library"
        )
        self.assertEqual(host["availability"], "measured")
        self.assertLess(host["candidate_bytes"], host["baseline_bytes"])
        self.assertIsInstance(host["delta_bytes"], int)
        self.assertNotEqual(host["baseline_bytes"], 0)
        for row in report["artifacts"]:
            if row["availability"] == "unavailable":
                self.assertIsNone(row["baseline_bytes"])
                self.assertIsNone(row["candidate_bytes"])
                self.assertIsNone(row["delta_bytes"])
                self.assertTrue(row["reason"])
        self.assertGreaterEqual(len(report["cpu_runs"]), 2)
        for row in report["cpu_runs"]:
            if row.get("availability") == "unavailable":
                self.assertIsNone(row.get("point_estimate"))
                self.assertTrue(row.get("reason"))
            else:
                self.assertIsNotNone(row.get("point_estimate"))

    def test_failed_cpu_does_not_publish_stale_or_missing_estimates(self):
        stale = write_criterion_estimates(self.root / "cpu-baseline", 12345.0)
        self.assertTrue(stale.is_file())
        isolate = self.root / "empty-target"
        isolate.mkdir()
        measure.isolate_criterion_dir(isolate)
        leftover = write_criterion_estimates(isolate, 999.0)
        measure.isolate_criterion_dir(isolate)
        self.assertFalse(leftover.exists())

        published = measure.cpu_rows_from_successful_run(
            "baseline",
            measure.BASELINE_PROFILE,
            measure.collect_cpu(self.root / "cpu-baseline"),
        )
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0]["point_estimate"], 12345.0)

        failed = measure.unavailable_cpu_row(
            "baseline",
            measure.BASELINE_PROFILE,
            "cpu-baseline failed with 2; see logs/cpu-baseline.stderr",
        )
        self.assertIsNone(failed["point_estimate"])
        self.assertEqual(failed["availability"], "unavailable")
        markdown = measure.render_markdown(
            {
                "schema_version": 1,
                "source_sha": "a" * 40,
                "builder_sha": "b" * 40,
                "artifacts": [],
                "cpu_runs": [failed],
                "cpu_collection_error": failed["reason"],
            }
        )
        self.assertIn("unavailable", markdown)
        self.assertNotIn("12345", markdown)
        self.assertIn("CPU collection failed", markdown)

    def test_cpu_measurement_gate_fails_with_and_without_stale_estimates(self):
        for label, seed_stale in (("without-stale", False), ("with-stale", True)):
            with self.subTest(label=label):
                work = self.root / label
                work.mkdir()
                measure_dir = work / "measure"
                if seed_stale:
                    write_criterion_estimates(measure_dir / "cpu-baseline", 4242.0)
                    write_criterion_estimates(measure_dir / "cpu-candidate", 4343.0)
                bin_dir = work / "bin"
                write_executable(
                    bin_dir / "cargo",
                    "#!/usr/bin/env python3\n"
                    "import sys\n"
                    "if sys.argv[1:2] == ['--version']:\n"
                    "    print('cargo 1.97.1')\n"
                    "    raise SystemExit(0)\n"
                    "raise SystemExit(2)\n",
                )
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                output = work / "report.json"
                markdown = work / "report.md"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(HERE / "measure-release-profile.py"),
                        "--source-sha",
                        "a" * 40,
                        "--builder-sha",
                        "b" * 40,
                        "--cpu",
                        "--work-dir",
                        str(measure_dir),
                        "--output",
                        str(output),
                        "--markdown",
                        str(markdown),
                    ],
                    env=env,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(completed.returncode, 0)
                report = json.loads(output.read_text())
                for row in report["cpu_runs"]:
                    self.assertIsNone(row.get("point_estimate"))
                    self.assertEqual(row.get("availability"), "unavailable")
                    self.assertTrue(row.get("reason"))
                rendered = markdown.read_text()
                self.assertNotIn("4242", rendered)
                self.assertNotIn("4343", rendered)
                self.assertIn("unavailable", rendered)


if __name__ == "__main__":
    unittest.main()
