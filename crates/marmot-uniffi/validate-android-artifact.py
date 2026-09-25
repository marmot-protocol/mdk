#!/usr/bin/env python3
"""Validate MarmotKit Android ELF load alignment and packaged reports.

Library mode checks one ABI's libmarmot_uniffi.so. Directory mode checks the
staged bundle and writes android-elf.json. Bundle mode recomputes that report
from the finished ZIP and requires it to match both the embedded report and
the staged report. ZIP alignment is not a substitute for PT_LOAD alignment.
"""

import argparse
import hashlib
import json
import stat
import struct
import sys
import zipfile
from pathlib import Path


ABIS = {
    "arm64-v8a": {"elf_class": 64, "machine": 183},
    "armeabi-v7a": {"elf_class": 32, "machine": 40},
    "x86": {"elf_class": 32, "machine": 3},
    "x86_64": {"elf_class": 64, "machine": 62},
}
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
LIBRARY_NAME = "libmarmot_uniffi.so"
REPORT_NAME = "android-elf.json"
SUPPORT_FILES = (
    "kotlin/dev/ipf/marmotkit/marmot_uniffi.kt",
    "kotlin/dev/ipf/marmotkit/MarmotAndroid.kt",
    "kotlin/io/crates/keyring/Keyring.kt",
)
MIN_64BIT_ALIGNMENT = 16384
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_PHNUM = 256
MAX_MEMBERS = 512
MAX_MEMBER_NAME = 240
ET_DYN = 3
PT_LOAD = 1
ELF_MAGIC = b"\x7fELF"


class ArtifactError(Exception):
    """The Android artifact failed validation."""


def library_relative(abi):
    return f"jniLibs/{abi}/{LIBRARY_NAME}"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path, limit, *, allow_empty=False):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ArtifactError(f"missing regular file: {candidate}")
    size = candidate.stat().st_size
    if size > limit or (size <= 0 and not allow_empty):
        raise ArtifactError(f"invalid file size: {candidate}")
    return candidate.read_bytes()


def parse_elf(data, abi):
    if abi not in ABIS:
        raise ArtifactError(f"unsupported ABI: {abi}")
    if len(data) > MAX_LIBRARY_BYTES:
        raise ArtifactError("oversized library")
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ArtifactError("not an ELF file" if data[:4] != ELF_MAGIC else "truncated ELF header")
    elf_class = data[4]
    elf_data = data[5]
    if elf_class not in (1, 2) or elf_data != 1 or data[6] != 1:
        raise ArtifactError("unsupported ELF encoding")
    expected = ABIS[abi]
    if (elf_class == 1 and expected["elf_class"] != 32) or (elf_class == 2 and expected["elf_class"] != 64):
        raise ArtifactError(f"unexpected ELF class for {abi}")
    if elf_class == 2:
        if len(data) < 64:
            raise ArtifactError("truncated ELF header")
        fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        ehsize, phentsize = 64, 56
    else:
        if len(data) < 52:
            raise ArtifactError("truncated ELF header")
        fields = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        ehsize, phentsize = 52, 32
    e_type, machine, version, _entry, phoff, _shoff, _flags, got_ehsize, got_phentsize, phnum = fields[:10]
    if version != 1:
        raise ArtifactError("unsupported ELF version")
    if got_ehsize != ehsize or got_phentsize != phentsize:
        raise ArtifactError("unexpected ELF header sizes")
    if e_type != ET_DYN:
        raise ArtifactError("ELF is not a shared object")
    if machine != expected["machine"]:
        raise ArtifactError(f"unexpected ELF machine for {abi}")
    if phnum <= 0 or phnum > MAX_PHNUM:
        raise ArtifactError("invalid program header count")
    table_bytes = phnum * phentsize
    if phoff < ehsize or phoff > len(data) or table_bytes > len(data) - phoff:
        raise ArtifactError("truncated program header table")
    loads = []
    for index in range(phnum):
        start = phoff + index * phentsize
        if elf_class == 2:
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                "<IIQQQQQQ", data, start
            )
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _flags, p_align = struct.unpack_from(
                "<IIIIIIII", data, start
            )
        if p_filesz > p_memsz:
            raise ArtifactError("segment file size exceeds memory size")
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            raise ArtifactError("segment extends past end of file")
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_align))
    if not loads:
        raise ArtifactError("ELF has no load segments")
    alignments = []
    for p_offset, p_vaddr, p_align in loads:
        if p_align <= 0 or p_align & (p_align - 1):
            raise ArtifactError("load alignment is not a power of two")
        if expected["elf_class"] == 64 and p_align < MIN_64BIT_ALIGNMENT:
            raise ArtifactError("64-bit load alignment is below 16 KB")
        if p_offset % p_align != p_vaddr % p_align:
            raise ArtifactError("load offset is not congruent to its virtual address")
        alignments.append(int(p_align))
    return {
        "abi": abi,
        "sha256": sha256(data),
        "elf_class": expected["elf_class"],
        "machine": machine,
        "load_alignments": alignments,
    }


def describe_libraries(blobs):
    libraries = {}
    for abi in ABI_ORDER:
        libraries[library_relative(abi)] = parse_elf(blobs[abi], abi)
    return {
        "schema_version": 1,
        "minimum_64bit_load_alignment": MIN_64BIT_ALIGNMENT,
        "libraries": libraries,
    }


def canonical_report(report):
    return json.dumps(report, sort_keys=True, separators=(",", ":"))


def parse_report(data):
    if len(data) > MAX_REPORT_BYTES:
        raise ArtifactError("oversized report")
    try:
        report = json.loads(data)
    except json.JSONDecodeError as error:
        raise ArtifactError("malformed report") from error
    if not isinstance(report, dict):
        raise ArtifactError("malformed report")
    return report


def reports_match(actual, expected):
    return canonical_report(actual) == canonical_report(expected)


def contained_file(root, relative, limit):
    root = Path(root).resolve()
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ArtifactError(f"unsafe path: {relative}")
    resolved = current.resolve()
    if not resolved.is_relative_to(root):
        raise ArtifactError(f"unsafe path: {relative}")
    return read_regular_file(resolved, limit)


def require_support_files(root):
    for relative in SUPPORT_FILES:
        contained_file(root, relative, MAX_LIBRARY_BYTES)


def read_bundle_libraries(root):
    return {abi: contained_file(root, library_relative(abi), MAX_LIBRARY_BYTES) for abi in ABI_ORDER}


def command_library(abi, path):
    parse_elf(read_regular_file(path, MAX_LIBRARY_BYTES, allow_empty=True), abi)


def command_directory(root, report_path):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ArtifactError("bundle root is not a directory")
    require_support_files(root)
    report = describe_libraries(read_bundle_libraries(root))
    destination = Path(report_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(payload)
    temporary.replace(destination)


def safe_member_name(name):
    if not isinstance(name, str) or len(name) > MAX_MEMBER_NAME or "\\" in name or "\x00" in name or name.startswith("/"):
        raise ArtifactError("unsafe archive member")
    parts = name.split("/")
    if name.endswith("/"):
        parts = parts[:-1]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ArtifactError("unsafe archive member")


def member_kind(info):
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ArtifactError("non-regular archive member")
    file_mode = stat.S_IFMT(mode)
    if file_mode not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ArtifactError("non-regular archive member")
    return info.is_dir() or name_is_dir(info.filename)


def name_is_dir(name):
    return name.endswith("/")


def check_root_name(root):
    if not root or "/" in root or "\\" in root or root in (".", "..") or "\x00" in root:
        raise ArtifactError("unsafe bundle root")


def command_bundle(archive_path, root_name, report_path):
    check_root_name(root_name)
    archive_path = Path(archive_path)
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ArtifactError("missing archive")
    if archive_path.stat().st_size <= 0 or archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArtifactError("oversized archive" if archive_path.stat().st_size > MAX_ARCHIVE_BYTES else "corrupt archive")
    try:
        archive = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as error:
        raise ArtifactError("corrupt archive") from error
    with archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ArtifactError("oversized archive")
        prefix = root_name + "/"
        expected_libraries = {prefix + library_relative(abi) for abi in ABI_ORDER}
        names = []
        uncompressed = 0
        for info in members:
            safe_member_name(info.filename)
            is_dir = member_kind(info)
            if not info.filename.startswith(prefix):
                raise ArtifactError("archive member outside bundle root")
            if not is_dir and info.filename.endswith(".so") and info.filename not in expected_libraries:
                raise ArtifactError(f"unexpected archive library: {info.filename[len(prefix):]}")
            if info.filename in names:
                raise ArtifactError("duplicate archive member")
            names.append(info.filename)
            if is_dir:
                continue
            if info.file_size <= 0 or info.file_size > MAX_LIBRARY_BYTES:
                raise ArtifactError("oversized archive member" if info.file_size > MAX_LIBRARY_BYTES else "truncated archive member")
            uncompressed += info.file_size
            if uncompressed > MAX_ARCHIVE_BYTES:
                raise ArtifactError("oversized archive")
            # Check every member's stream and CRC, including provenance and
            # manifests that are not otherwise read by this validator.
            try:
                with archive.open(info) as stream:
                    while stream.read(1024 * 1024):
                        pass
            except (OSError, RuntimeError, zipfile.BadZipFile, EOFError) as error:
                raise ArtifactError("corrupt archive") from error
        blobs = {}
        for abi in ABI_ORDER:
            member = prefix + library_relative(abi)
            if names.count(member) != 1:
                raise ArtifactError(f"missing archive library: {library_relative(abi)}")
            blobs[abi] = read_zip_member(archive, member)
        for relative in SUPPORT_FILES:
            member = prefix + relative
            if names.count(member) != 1:
                raise ArtifactError(f"missing archive file: {relative}")
            support = read_zip_member(archive, member)
            if not support:
                raise ArtifactError(f"missing archive file: {relative}")
        report_member = prefix + REPORT_NAME
        if names.count(report_member) != 1:
            raise ArtifactError("missing embedded report")
        embedded = parse_report(read_zip_member(archive, report_member))
    recomputed = describe_libraries(blobs)
    if not reports_match(embedded, recomputed):
        raise ArtifactError("embedded report does not match library bytes")
    staged = parse_report(read_regular_file(report_path, MAX_REPORT_BYTES))
    if not reports_match(staged, recomputed):
        raise ArtifactError("staged report does not match library bytes")


def read_zip_member(archive, name):
    try:
        data = archive.read(name)
    except (KeyError, zipfile.BadZipFile, RuntimeError) as error:
        raise ArtifactError("corrupt archive") from error
    info = archive.getinfo(name)
    if len(data) != info.file_size:
        raise ArtifactError("truncated archive member")
    return data


def build_parser():
    parser = argparse.ArgumentParser(prog="validate-android-artifact.py")
    commands = parser.add_subparsers(dest="command", required=True)
    library = commands.add_parser("library")
    library.add_argument("--abi", required=True, choices=ABI_ORDER)
    library.add_argument("file")
    directory = commands.add_parser("directory")
    directory.add_argument("root")
    directory.add_argument("--report", required=True)
    bundle = commands.add_parser("bundle")
    bundle.add_argument("zip")
    bundle.add_argument("--root", required=True)
    bundle.add_argument("--report", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "library":
            command_library(args.abi, args.file)
        elif args.command == "directory":
            command_directory(args.root, args.report)
        else:
            command_bundle(args.zip, args.root, args.report)
    except ArtifactError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
