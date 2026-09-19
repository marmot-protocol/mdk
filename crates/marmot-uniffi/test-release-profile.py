#!/usr/bin/env python3
"""Release-profile parity, provenance JSON, and builder-control regressions."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest


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
        if len(encoded) > 16:
            raise ValueError(name)
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


def macho64_trailing_llvm(little: bool, payload: bytes) -> bytes:
    """64-bit Mach-O with empty __TEXT plus a trailing __LLVM bitcode payload."""
    cmdsize = 72
    header_size = 32
    sizeofcmds = cmdsize * 2
    fileoff = header_size + sizeofcmds

    def segment(name: bytes, off: int, size: int) -> bytes:
        return (
            _pack("I", 0x19, little=little)
            + _pack("I", cmdsize, little=little)
            + name.ljust(16, b"\0")
            + _pack("Q", 0, little=little)
            + _pack("Q", size, little=little)
            + _pack("Q", off, little=little)
            + _pack("Q", size, little=little)
            + _pack("i", 0, little=little)
            + _pack("i", 0, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", 0, little=little)
        )

    header = (
        _pack("I", 0xFEEDFACF, little=little)
        + _pack("i", 0x0100000C, little=little)
        + _pack("i", 0, little=little)
        + _pack("I", 1, little=little)
        + _pack("I", 2, little=little)
        + _pack("I", sizeofcmds, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    return header + segment(b"__TEXT", 0, 0) + segment(b"__LLVM", fileoff, len(payload)) + payload


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


def macho64_mh_object_midfile_llvm_with_version_min(
    little: bool,
    leading: bytes,
    bitcode: bytes,
    trailing: bytes,
    extra_cmd: bytes | None = None,
) -> bytes:
    """MH_OBJECT with mid-file __LLVM,__bitcode plus LC_VERSION_MIN_IPHONEOS."""
    header_size = 32
    nsects = 3
    segment_cmdsize = 72 + 80 * nsects
    version_cmdsize = 16
    extra = extra_cmd or b""
    sizeofcmds = segment_cmdsize + version_cmdsize + len(extra)
    ncmds = 2 + (1 if extra else 0)
    lead_off = header_size + sizeofcmds
    bitcode_off = lead_off + len(leading)
    trail_off = bitcode_off + len(bitcode)
    total = trail_off + len(trailing)

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
        + _pack("I", ncmds, little=little)
        + _pack("I", sizeofcmds, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    segment = (
        _pack("I", 0x19, little=little)
        + _pack("I", segment_cmdsize, little=little)
        + b"__TEXT".ljust(16, b"\0")
        + _pack("Q", 0, little=little)
        + _pack("Q", total, little=little)
        + _pack("Q", 0, little=little)
        + _pack("Q", total, little=little)
        + _pack("i", 7, little=little)
        + _pack("i", 7, little=little)
        + _pack("I", nsects, little=little)
        + _pack("I", 0, little=little)
        + section(b"__text", b"__TEXT", 0, len(leading), lead_off)
        + section(b"__bitcode", b"__LLVM", len(leading), len(bitcode), bitcode_off)
        + section(b"__const", b"__TEXT", len(leading) + len(bitcode), len(trailing), trail_off)
    )
    version = (
        _pack("I", 0x25, little=little)
        + _pack("I", version_cmdsize, little=little)
        + _pack("I", 0x00120000, little=little)
        + _pack("I", 0x00120000, little=little)
    )
    return header + segment + version + extra + leading + bitcode + trailing


def macho64_mh_object_bitcode_at_segment_fileoff(
    little: bool,
    native: bytes,
    bitcode: bytes,
    *,
    segment_fileoff: int = 784,
    extra_cmd: bytes | None = None,
    native_fileoff: int | None = None,
) -> bytes:
    """MH_OBJECT whose parent __TEXT fileoff equals leftover bitcode.

    Exact-head macOS CI on 9dfab7008e1748a46df9b9240bb678fb4124d46c failed
    with `segment offset 784 lands inside removed bitcode` because rustc
    compiler_builtins members set the segment fileoff to the first section,
    which is leftover `__LLVM,__bitcode`, while native `__text` follows.
    """
    header_size = 32
    nsects = 2
    segment_cmdsize = 72 + 80 * nsects
    version_cmdsize = 16
    extra = extra_cmd or b""
    sizeofcmds = segment_cmdsize + version_cmdsize + len(extra)
    ncmds = 2 + (1 if extra else 0)
    commands_end = header_size + sizeofcmds
    if segment_fileoff < commands_end:
        raise ValueError("segment_fileoff overlaps load commands")
    bitcode_off = segment_fileoff
    text_off = native_fileoff if native_fileoff is not None else bitcode_off + len(bitcode)
    reloc_off = text_off + len(native)
    filesize = (text_off + len(native)) - segment_fileoff

    def section(
        sectname: bytes,
        segname: bytes,
        addr: int,
        size: int,
        offset: int,
        reloff: int = 0,
        nreloc: int = 0,
    ) -> bytes:
        return (
            sectname.ljust(16, b"\0")
            + segname.ljust(16, b"\0")
            + _pack("Q", addr, little=little)
            + _pack("Q", size, little=little)
            + _pack("I", offset, little=little)
            + _pack("I", 0, little=little)
            + _pack("I", reloff, little=little)
            + _pack("I", nreloc, little=little)
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
        + _pack("I", ncmds, little=little)
        + _pack("I", sizeofcmds, little=little)
        + _pack("I", 0, little=little)
        + _pack("I", 0, little=little)
    )
    segment = (
        _pack("I", 0x19, little=little)
        + _pack("I", segment_cmdsize, little=little)
        + b"__TEXT".ljust(16, b"\0")
        + _pack("Q", 0, little=little)
        + _pack("Q", filesize, little=little)
        + _pack("Q", segment_fileoff, little=little)
        + _pack("Q", filesize, little=little)
        + _pack("i", 7, little=little)
        + _pack("i", 7, little=little)
        + _pack("I", nsects, little=little)
        + _pack("I", 0, little=little)
        + section(b"__bitcode", b"__LLVM", 0, len(bitcode), bitcode_off)
        + section(
            b"__text",
            b"__TEXT",
            len(bitcode),
            len(native),
            text_off,
            reloff=reloc_off,
            nreloc=1,
        )
    )
    version = (
        _pack("I", 0x25, little=little)
        + _pack("I", version_cmdsize, little=little)
        + _pack("I", 0x00120000, little=little)
        + _pack("I", 0x00120000, little=little)
    )
    pad = bytes(segment_fileoff - commands_end)
    reloc = _pack("I", 0, little=little) + _pack("I", 0, little=little)
    return header + segment + version + extra + pad + bitcode + native + reloc


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

    def test_sanitize_removes_llvm_from_compiler_builtins_named_member(self):
        native = macho64(True, b"__TEXT")
        llvm = macho64(True, b"__LLVM")
        path = self.root / "libmarmot_uniffi.a"
        archive.write_archive(
            path,
            [
                ("obj.o", native),
                (
                    "compiler_builtins-c474715e2ac50578.compiler_builtins.498324e461c21fb7-cgu.227.rcgu.o",
                    llvm,
                ),
            ],
        )
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(path)
        count = archive.sanitize_archive(path)
        self.assertEqual(count, 2)
        self.assertGreater(archive.check_archive(path), 0)
        names = [name for _, name, _ in archive.iter_ar_members(path.read_bytes())]
        self.assertTrue(
            any(name.startswith("compiler_builtins-") for name in names),
            names,
        )
        trailing = self.root / "trailing-llvm.a"
        payload = b"\x00" * 0xE80
        archive.write_archive(
            trailing,
            [
                (
                    "compiler_builtins-c474715e2ac50578.compiler_builtins.498324e461c21fb7-cgu.227.rcgu.o",
                    macho64_trailing_llvm(True, payload),
                )
            ],
        )
        self.assertTrue(archive.member_has_bitcode(macho64_trailing_llvm(True, payload)))
        archive.sanitize_archive(trailing)
        members = list(archive.iter_ar_members(trailing.read_bytes()))
        self.assertEqual(len(members), 1)
        self.assertFalse(archive.member_has_bitcode(members[0][2]))
        self.assertLess(len(members[0][2]), 0xE80)

    def test_sanitize_removes_mh_object_section_level_llvm_bitcode(self):
        native = b"NATIVEOBJ"
        bitcode = b"\x11" * 0xE80
        member = macho64_mh_object_text_and_llvm(True, native, bitcode)
        path = self.root / "compiler-builtins-mh-object.a"
        archive.write_archive(
            path,
            [
                (
                    "compiler_builtins-c474715e2ac50578.compiler_builtins.498324e461c21fb7-cgu.227.rcgu.o",
                    member,
                )
            ],
        )
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(path)
        count = archive.sanitize_archive(path)
        self.assertEqual(count, 1)
        names = [name for _, name, content in archive.iter_ar_members(path.read_bytes())]
        self.assertTrue(any(name.startswith("compiler_builtins-") for name in names), names)
        stripped = list(archive.iter_ar_members(path.read_bytes()))[0][2]
        self.assertFalse(archive.member_has_bitcode(stripped))
        self.assertIn(native, stripped)
        self.assertNotIn(bitcode, stripped)
        self.assertLess(len(stripped), len(member))
        text_only = macho64(True, b"__TEXT", sectname=b"__bitcode")
        text_path = self.root / "text-bitcode-section.a"
        archive.write_archive(text_path, [("obj.o", text_only)])
        archive.sanitize_archive(text_path)
        self.assertFalse(
            archive.member_has_bitcode(list(archive.iter_ar_members(text_path.read_bytes()))[0][2])
        )
        bundle = macho64_mh_object_text_and_llvm(True, native, bitcode, llvm_sectname=b"__bundle")
        bundle_path = self.root / "llvm-bundle.a"
        archive.write_archive(bundle_path, [("obj.o", bundle)])
        archive.sanitize_archive(bundle_path)
        self.assertFalse(
            archive.member_has_bitcode(list(archive.iter_ar_members(bundle_path.read_bytes()))[0][2])
        )

    def test_sanitize_preserves_version_min_after_midfile_bitcode_removal(self):
        leading = b"LEADINGOBJ"
        bitcode = b"\x22" * 0xE80
        trailing = b"TRAILINGOBJ"
        uuid = (
            struct.pack("<I", 0x1B)
            + struct.pack("<I", 24)
            + bytes(range(16))
        )
        member = macho64_mh_object_midfile_llvm_with_version_min(
            True, leading, bitcode, trailing, extra_cmd=uuid
        )
        path = self.root / "midfile-version-min.a"
        archive.write_archive(
            path,
            [
                (
                    "compiler_builtins-c474715e2ac50578.compiler_builtins.498324e461c21fb7-cgu.227.rcgu.o",
                    member,
                )
            ],
        )
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(path)
        count = archive.sanitize_archive(path)
        self.assertEqual(count, 1)
        stripped = list(archive.iter_ar_members(path.read_bytes()))[0][2]
        self.assertFalse(archive.member_has_bitcode(stripped))
        self.assertIn(leading, stripped)
        self.assertIn(trailing, stripped)
        self.assertNotIn(bitcode, stripped)
        self.assertIn(struct.pack("<I", 0x25), stripped)
        self.assertIn(bytes(range(16)), stripped)
        self.assertLess(len(stripped), len(member))

    def test_sanitize_snaps_segment_fileoff_off_leading_bitcode(self):
        native = b"NATIVE784"
        bitcode = b"\x44" * 0xE80
        member = macho64_mh_object_bitcode_at_segment_fileoff(True, native, bitcode)
        path = self.root / "segment-fileoff-784.a"
        archive.write_archive(
            path,
            [
                (
                    "compiler_builtins-c474715e2ac50578.compiler_builtins.498324e461c21fb7-cgu.227.rcgu.o",
                    member,
                )
            ],
        )
        with self.assertRaises(archive.ArchiveError):
            archive.check_archive(path)
        count = archive.sanitize_archive(path)
        self.assertEqual(count, 1)
        stripped = list(archive.iter_ar_members(path.read_bytes()))[0][2]
        self.assertFalse(archive.member_has_bitcode(stripped))
        self.assertIn(native, stripped)
        self.assertNotIn(bitcode, stripped)
        self.assertIn(struct.pack("<I", 0x25), stripped)
        self.assertLess(len(stripped), len(member))
        fileoff = struct.unpack_from("<Q", stripped, 32 + 40)[0]
        filesize = struct.unpack_from("<Q", stripped, 32 + 48)[0]
        self.assertEqual(fileoff, 784)
        self.assertEqual(filesize, len(native))
        text_off = struct.unpack_from("<I", stripped, 32 + 72 + 48)[0]
        reloff = struct.unpack_from("<I", stripped, 32 + 72 + 56)[0]
        self.assertEqual(text_off, 784)
        self.assertEqual(reloff, 784 + len(native))

    def test_sanitize_still_rejects_section_offset_inside_removed_bitcode(self):
        native = b"NATIVE784"
        bitcode = b"\x55" * 0xE80
        member = macho64_mh_object_bitcode_at_segment_fileoff(
            True, native, bitcode, native_fileoff=800
        )
        path = self.root / "section-inside-bitcode.a"
        archive.write_archive(path, [("obj.o", member)])
        with self.assertRaisesRegex(archive.ArchiveError, "section offset 800 lands inside removed bitcode"):
            archive.sanitize_archive(path)

    def test_sanitize_still_rejects_unknown_midfile_load_command(self):
        unknown = struct.pack("<I", 0x99) + struct.pack("<I", 8)
        member = macho64_mh_object_midfile_llvm_with_version_min(
            True, b"LEADINGOBJ", b"\x33" * 0x80, b"TRAILINGOBJ", extra_cmd=unknown
        )
        path = self.root / "unknown-midfile.a"
        archive.write_archive(path, [("obj.o", member)])
        with self.assertRaisesRegex(archive.ArchiveError, "unknown Mach-O load command 0x99"):
            archive.sanitize_archive(path)

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
            " 'codegen': os.environ.get('CARGO_PROFILE_RELEASE_CODEGEN_UNITS')}\n"
            "with log.open('a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps(entry) + '\\n')\n"
            "args = sys.argv[1:]\n"
            "target_dir = Path(os.environ['CARGO_TARGET_DIR'])\n"
            "if args and args[0] == 'build':\n"
            "    triple = None\n"
            "    if '--target' in args:\n"
            "        triple = args[args.index('--target') + 1]\n"
            "    if triple:\n"
            "        out = target_dir / triple / 'release' / 'libmarmot_uniffi.so'\n"
            "    else:\n"
            "        out = target_dir / 'release' / 'libmarmot_uniffi.so'\n"
            "    out.parent.mkdir(parents=True, exist_ok=True)\n"
            "    out.write_bytes(b'library')\n"
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
        env = os.environ.copy()
        env["HOME"] = str(self.root / "home-kotlin")
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["ANDROID_NDK_HOME"] = str(self.root / "ndk")
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
        self.assertTrue((crate / "output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt").is_file())

    def test_kotlin_generation_is_required(self):
        log = self.root / "cargo.jsonl"
        log.write_text("")
        bin_dir = self.root / "bin"
        workspace = self.root / "old-source"
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
        self.assertTrue((crate / extras["output"]).exists())

    def test_profile_workflow_is_non_publishing(self):
        text = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        self.assertIn("persist-credentials: false", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("softprops/action-gh-release", text)
        self.assertNotIn("upload-to-github-release", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertGreaterEqual(text.count("if: always()"), 4)
        self.assertIn("--diagnostics-dir", text)
        self.assertIn("target/release-profile-measure/logs", text)
        self.assertIn("cpu-${variant}/criterion", text)
        self.assertIn("xcodebuild -version", text)

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
