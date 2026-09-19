#!/usr/bin/env python3
"""Reject LLVM bitcode in packaged Apple static archives.

Walks every archive member, including duplicate names. Extraction that
collapses names is not used. Byte-level bitcode magic is always checked.
When Apple otool output is available, embedded __LLVM / __bitcode sections
are rejected as well.

Apple Cargo invocations must pass `-C embed-bitcode=no` because rustc
defaults to embedding bitcode on Apple targets. The toolchain's
compiler_builtins objects can still retain leftover `__LLVM,__bitcode`
data. Relocatable MH_OBJECT members often keep those sections inside a
parent `__TEXT` load command, with `segname __LLVM` on the section
itself. `--sanitize` removes those Mach-O segments and section-level
`__LLVM` / `__bitcode` leftovers from every member without skipping
names. Offset-free load commands such as `LC_VERSION_MIN_IPHONEOS`
are left unchanged when leftover bitcode is removed from the middle
of a member. A parent segment whose `fileoff` equals that leftover
bitcode start is snapped to the remaining native data; pointers that
land strictly inside removed bitcode still fail closed. Raw LLVM
bitcode members still fail closed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path


AR_MAGIC = b"!<arch>\n"
LLVM_BITCODE_MAGIC = b"BC\xc0\xde"
LLVM_WRAPPER_MAGIC = bytes((0xDE, 0xC0, 0x17, 0x0B))
MACHO_MAGICS = {
    0xFEEDFACE,
    0xCEFAEDFE,
    0xFEEDFACF,
    0xCFFAEDFE,
    0xCAFEBABE,
    0xBEBAFECA,
}
# Values produced by decoding the first word with "<I". Native little-endian
# 32/64-bit Mach-O and the usual FAT_MAGIC on a little-endian read.
LITTLE_ENDIAN_ON_LE_DECODE = {
    0xFEEDFACE,
    0xFEEDFACF,
    0xCAFEBABE,
}
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_NOTE = 0x31
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x33
LC_DYLD_CHAINED_FIXUPS = 0x34
LC_ATOM_INFO = 0x36
EMBED_BITCODE_RUSTFLAG = "-C embed-bitcode=no"
LINKEDIT_DATA_COMMANDS = {
    LC_CODE_SIGNATURE,
    LC_SEGMENT_SPLIT_INFO,
    LC_FUNCTION_STARTS,
    LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_ATOM_INFO,
}
# These commands carry no file offsets, so mid-file bitcode removal must
# keep their payloads intact. 0x25 is LC_VERSION_MIN_IPHONEOS.
OFFSET_FREE_COMMANDS = {
    LC_UUID,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_IPHONEOS,
    LC_SOURCE_VERSION,
    LC_LINKER_OPTION,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LC_BUILD_VERSION,
}


def _cname(raw: bytes) -> bytes:
    return raw.split(b"\0", 1)[0]


def _section_is_llvm_bitcode(sectname: bytes, section_segname: bytes) -> bool:
    """True for leftover Apple bitcode, including MH_OBJECT section fields."""
    return sectname == b"__bitcode" or section_segname == b"__LLVM"


def _range_overlap(start: int, end: int, other_start: int, other_end: int) -> int:
    return max(0, min(end, other_end) - max(start, other_start))


class ArchiveError(ValueError):
    """The archive is malformed or contains unexpected bitcode."""


def iter_ar_members(data: bytes):
    if not data.startswith(AR_MAGIC):
        raise ArchiveError("not a Unix static archive")
    offset = len(AR_MAGIC)
    index = 0
    while offset < len(data):
        if offset + 60 > len(data):
            raise ArchiveError("truncated archive member header")
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise ArchiveError("invalid archive member header")
        name = header[0:16].decode("ascii", "replace").rstrip()
        size_field = header[48:58].decode("ascii", "replace").strip()
        if not size_field.isdigit():
            raise ArchiveError(f"invalid archive member size for {name}")
        size = int(size_field)
        offset += 60
        if name.startswith("#1/"):
            try:
                name_len = int(name[3:])
            except ValueError as error:
                raise ArchiveError(f"invalid BSD long name length for {name}") from error
            if offset + size > len(data) or name_len > size:
                raise ArchiveError(f"truncated BSD long name for {name}")
            raw_name = data[offset : offset + name_len]
            name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
            content = data[offset + name_len : offset + size]
            consumed = size
        else:
            if offset + size > len(data):
                raise ArchiveError(f"truncated archive member {name}")
            content = data[offset : offset + size]
            consumed = size
        yield index, name, content
        index += 1
        offset += consumed
        if offset % 2 == 1:
            offset += 1


def _u32(data: bytes, offset: int, little: bool) -> int:
    fmt = "<I" if little else ">I"
    return struct.unpack_from(fmt, data, offset)[0]


def macho_has_llvm_bitcode(content: bytes) -> bool:
    if len(content) < 8:
        return False
    magic = struct.unpack_from("<I", content, 0)[0]
    if magic not in MACHO_MAGICS and struct.unpack_from(">I", content, 0)[0] not in MACHO_MAGICS:
        return False
    little = magic in LITTLE_ENDIAN_ON_LE_DECODE
    magic = _u32(content, 0, little)
    if magic in {0xCAFEBABE, 0xBEBAFECA}:
        return b"__LLVM" in content or b"__bitcode" in content
    is_64 = magic in {0xFEEDFACF, 0xCFFAEDFE}
    header_size = 32 if is_64 else 28
    if len(content) < header_size:
        return False
    ncmds = _u32(content, 16, little)
    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(content):
            return False
        cmd = _u32(content, offset, little)
        cmdsize = _u32(content, offset + 4, little)
        if cmdsize < 8 or offset + cmdsize > len(content):
            return False
        if cmd in {LC_SEGMENT, LC_SEGMENT_64}:
            name_off = offset + 8
            segname = content[name_off : name_off + 16].split(b"\0", 1)[0]
            if segname == b"__LLVM":
                return True
            section_size = 80 if cmd == LC_SEGMENT_64 else 68
            nsects_off = offset + (64 if cmd == LC_SEGMENT_64 else 48)
            if nsects_off + 4 <= offset + cmdsize:
                nsects = _u32(content, nsects_off, little)
                sect = offset + (72 if cmd == LC_SEGMENT_64 else 56)
                for _ in range(nsects):
                    if sect + 32 > offset + cmdsize:
                        break
                    sectname = content[sect : sect + 16].split(b"\0", 1)[0]
                    section_segname = content[sect + 16 : sect + 32].split(b"\0", 1)[0]
                    if _section_is_llvm_bitcode(sectname, section_segname):
                        return True
                    sect += section_size
        offset += cmdsize
    return False


def member_has_bitcode(content: bytes) -> bool:
    if content.startswith(LLVM_BITCODE_MAGIC) or content.startswith(LLVM_WRAPPER_MAGIC):
        return True
    return macho_has_llvm_bitcode(content)


def otool_output_has_bitcode(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "segname __LLVM" or stripped.startswith("segname __LLVM"):
            return True
        if stripped == "sectname __bitcode" or stripped.startswith("sectname __bitcode"):
            return True
    return False


def inspect_otool(path: Path, otool_output: str | None = None) -> None:
    text = otool_output
    if text is None:
        otool = shutil.which("otool")
        xcrun = shutil.which("xcrun")
        if xcrun:
            command = ["xcrun", "otool", "-l", str(path)]
        elif otool:
            command = [otool, "-l", str(path)]
        else:
            return
        text = subprocess.check_output(command, text=True)
    if otool_output_has_bitcode(text):
        raise ArchiveError(f"{path} contains LLVM bitcode in otool load commands")


def check_archive(path: Path, otool_output: str | None = None) -> int:
    data = path.read_bytes()
    members = list(iter_ar_members(data))
    if not members:
        raise ArchiveError(f"{path} contains no archive members")
    for index, name, content in members:
        if member_has_bitcode(content):
            raise ArchiveError(
                f"{path} member {index} ({name}) contains LLVM bitcode"
            )
    inspect_otool(path, otool_output)
    return len(members)


def apple_target_rustflags_key(triple: str) -> str:
    return f"CARGO_TARGET_{triple.upper().replace('-', '_')}_RUSTFLAGS"


def apply_apple_native_archive_rustflags(env: dict[str, str], triple: str) -> dict[str, str]:
    """Keep Apple rustc from embedding bitcode; do not replace other target flags."""
    updated = dict(env)
    key = apple_target_rustflags_key(triple)
    current = updated.get(key, "")
    if "embed-bitcode=no" not in current:
        updated[key] = f"{current} {EMBED_BITCODE_RUSTFLAG}".strip()
    return updated


def _u64(data: bytes, offset: int, little: bool) -> int:
    fmt = "<Q" if little else ">Q"
    return struct.unpack_from(fmt, data, offset)[0]


def _pack32(value: int, little: bool) -> bytes:
    return struct.pack("<I" if little else ">I", value)


def _pack64(value: int, little: bool) -> bytes:
    return struct.pack("<Q" if little else ">Q", value)


def _adjust_offset(value: int, removed: list[tuple[int, int]], name: str) -> int:
    delta = 0
    for start, size in removed:
        if size <= 0:
            continue
        if start <= value < start + size:
            raise ArchiveError(f"{name} offset {value} lands inside removed bitcode")
        if value >= start + size:
            delta += size
    return value - delta


def _first_kept_offset(
    value: int, extent: int, removed: list[tuple[int, int]], name: str
) -> int:
    """Move a file offset forward out of removed bitcode when later bytes remain.

    Relocatable MH_OBJECT members often set the parent segment `fileoff` to
    the first section's file offset. When that first section is leftover
    `__LLVM,__bitcode`, the segment still covers the following native
    sections. After those bitcode bytes are deleted, the next kept data
    slides to the original bitcode start.
    """
    if extent <= 0:
        return 0
    end = value + extent
    snapped = value
    moved = True
    while moved:
        moved = False
        for start, size in removed:
            if size <= 0:
                continue
            removed_end = start + size
            if start <= snapped < removed_end:
                if end > removed_end:
                    snapped = removed_end
                    moved = True
                    break
                raise ArchiveError(f"{name} offset {value} lands inside removed bitcode")
    return snapped


def _relocated_segment_file(
    fileoff: int, filesize: int, removed: list[tuple[int, int]]
) -> tuple[int, int]:
    overlap = sum(
        _range_overlap(fileoff, fileoff + filesize, start, start + size)
        for start, size in removed
        if size > 0
    )
    new_filesize = max(0, filesize - overlap)
    if new_filesize == 0:
        return 0, 0
    if fileoff or filesize:
        snapped = _first_kept_offset(fileoff, filesize, removed, "segment")
        return _adjust_offset(snapped, removed, "segment"), new_filesize
    return fileoff, new_filesize


def _patch_u32(raw: bytearray, offset: int, little: bool, value: int) -> None:
    raw[offset : offset + 4] = _pack32(value, little)


def _patch_u64(raw: bytearray, offset: int, little: bool, value: int) -> None:
    raw[offset : offset + 8] = _pack64(value, little)


def _adjust_known_command(raw: bytes, cmd: int, little: bool, removed: list[tuple[int, int]]) -> bytes:
    patched = bytearray(raw)
    if cmd in {LC_SEGMENT, LC_SEGMENT_64}:
        is_64 = cmd == LC_SEGMENT_64
        fileoff_at = 40 if is_64 else 32
        filesize_at = 48 if is_64 else 36
        if is_64:
            fileoff = _u64(raw, fileoff_at, little)
            filesize = _u64(raw, filesize_at, little)
            new_off, new_filesize = _relocated_segment_file(fileoff, filesize, removed)
            _patch_u64(patched, fileoff_at, little, new_off)
            _patch_u64(patched, filesize_at, little, new_filesize)
        else:
            fileoff = _u32(raw, fileoff_at, little)
            filesize = _u32(raw, filesize_at, little)
            new_off, new_filesize = _relocated_segment_file(fileoff, filesize, removed)
            _patch_u32(patched, fileoff_at, little, new_off)
            _patch_u32(patched, filesize_at, little, new_filesize)
        section_size = 80 if is_64 else 68
        nsects_off = 64 if is_64 else 48
        nsects = _u32(raw, nsects_off, little)
        sect = 72 if is_64 else 56
        for _ in range(nsects):
            if is_64:
                offset = _u32(raw, sect + 48, little)
                reloff = _u32(raw, sect + 56, little)
                if offset:
                    _patch_u32(
                        patched, sect + 48, little, _adjust_offset(offset, removed, "section")
                    )
                if reloff:
                    _patch_u32(
                        patched, sect + 56, little, _adjust_offset(reloff, removed, "reloc")
                    )
            else:
                offset = _u32(raw, sect + 40, little)
                reloff = _u32(raw, sect + 48, little)
                if offset:
                    _patch_u32(
                        patched, sect + 40, little, _adjust_offset(offset, removed, "section")
                    )
                if reloff:
                    _patch_u32(
                        patched, sect + 48, little, _adjust_offset(reloff, removed, "reloc")
                    )
            sect += section_size
        return bytes(patched)
    if cmd == LC_SYMTAB:
        _patch_u32(patched, 8, little, _adjust_offset(_u32(raw, 8, little), removed, "symtab"))
        _patch_u32(patched, 16, little, _adjust_offset(_u32(raw, 16, little), removed, "strtab"))
        return bytes(patched)
    if cmd == LC_DYSYMTAB:
        for field_off, label in (
            (12, "tocoff"),
            (20, "modtaboff"),
            (28, "extrefsymoff"),
            (36, "indirectsymoff"),
            (44, "extreloff"),
            (52, "locreloff"),
        ):
            if field_off + 4 <= len(raw):
                _patch_u32(
                    patched,
                    field_off,
                    little,
                    _adjust_offset(_u32(raw, field_off, little), removed, label),
                )
        return bytes(patched)
    if cmd in {LC_DYLD_INFO, LC_DYLD_INFO_ONLY}:
        for field_off, label in (
            (8, "rebase_off"),
            (16, "bind_off"),
            (24, "weak_bind_off"),
            (32, "lazy_bind_off"),
            (40, "export_off"),
        ):
            if field_off + 4 <= len(raw):
                _patch_u32(
                    patched,
                    field_off,
                    little,
                    _adjust_offset(_u32(raw, field_off, little), removed, label),
                )
        return bytes(patched)
    if cmd in LINKEDIT_DATA_COMMANDS or cmd in {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64}:
        _patch_u32(patched, 8, little, _adjust_offset(_u32(raw, 8, little), removed, "linkedit"))
        return bytes(patched)
    if cmd == LC_NOTE:
        _patch_u64(patched, 24, little, _adjust_offset(_u64(raw, 24, little), removed, "note"))
        return bytes(patched)
    if cmd in OFFSET_FREE_COMMANDS:
        return raw
    if removed:
        raise ArchiveError(f"unknown Mach-O load command {cmd:#x} after mid-file bitcode removal")
    return raw


def _section_file_range(
    raw: bytes, sect: int, is_64: bool, little: bool
) -> list[tuple[int, int]]:
    if is_64:
        size = _u64(raw, sect + 40, little)
        fileoff = _u32(raw, sect + 48, little)
        reloff = _u32(raw, sect + 56, little)
        nreloc = _u32(raw, sect + 60, little)
    else:
        size = _u32(raw, sect + 36, little)
        fileoff = _u32(raw, sect + 40, little)
        reloff = _u32(raw, sect + 48, little)
        nreloc = _u32(raw, sect + 52, little)
    ranges = []
    if size and fileoff > 0:
        ranges.append((fileoff, size))
    if nreloc and reloff > 0:
        ranges.append((reloff, nreloc * 8))
    return ranges


def _strip_segment_command(
    raw: bytes, cmd: int, little: bool
) -> tuple[bytes | None, list[tuple[int, int]]]:
    """Drop leftover LLVM bitcode from one segment command.

    MH_OBJECT files keep `__LLVM,__bitcode` as sections inside a parent
    `__TEXT` load command. Those section-level leftovers are removed here
    instead of failing closed or skipping the member.
    """
    is_64 = cmd == LC_SEGMENT_64
    segname = _cname(raw[8:24])
    section_size = 80 if is_64 else 68
    nsects_off = 64 if is_64 else 48
    nsects = _u32(raw, nsects_off, little) if nsects_off + 4 <= len(raw) else 0
    header_len = 72 if is_64 else 56
    sect = header_len
    native: list[bytes] = []
    removed: list[tuple[int, int]] = []
    for _ in range(nsects):
        if sect + 32 > len(raw):
            raise ArchiveError("truncated Mach-O section while removing bitcode")
        sectname = _cname(raw[sect : sect + 16])
        section_segname = _cname(raw[sect + 16 : sect + 32])
        if _section_is_llvm_bitcode(sectname, section_segname) or segname == b"__LLVM":
            removed.extend(_section_file_range(raw, sect, is_64, little))
        else:
            native.append(raw[sect : sect + section_size])
        sect += section_size
    if not native:
        if nsects == 0 and segname == b"__LLVM":
            if is_64:
                fileoff = _u64(raw, 40, little)
                filesize = _u64(raw, 48, little)
            else:
                fileoff = _u32(raw, 32, little)
                filesize = _u32(raw, 36, little)
            if filesize and fileoff > 0:
                removed.append((fileoff, filesize))
        return None, removed
    new_cmdsize = header_len + section_size * len(native)
    rebuilt = bytearray(raw[:header_len])
    rebuilt[4:8] = _pack32(new_cmdsize, little)
    _patch_u32(rebuilt, nsects_off, little, len(native))
    for section in native:
        rebuilt.extend(section)
    return bytes(rebuilt), removed


def _strip_thin_macho(content: bytes) -> bytes:
    magic_le = struct.unpack_from("<I", content, 0)[0]
    little = magic_le in LITTLE_ENDIAN_ON_LE_DECODE
    magic = _u32(content, 0, little)
    is_64 = magic in {0xFEEDFACF, 0xCFFAEDFE}
    header_size = 32 if is_64 else 28
    if len(content) < header_size:
        raise ArchiveError("truncated Mach-O header")
    ncmds = _u32(content, 16, little)
    sizeofcmds = _u32(content, 20, little)
    if header_size + sizeofcmds > len(content):
        raise ArchiveError("truncated Mach-O load commands")
    kept: list[bytes] = []
    removed_ranges: list[tuple[int, int]] = []
    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > header_size + sizeofcmds:
            raise ArchiveError("truncated Mach-O load command")
        cmd = _u32(content, offset, little)
        cmdsize = _u32(content, offset + 4, little)
        if cmdsize < 8 or offset + cmdsize > header_size + sizeofcmds:
            raise ArchiveError("invalid Mach-O load command size")
        raw = content[offset : offset + cmdsize]
        if cmd in {LC_SEGMENT, LC_SEGMENT_64}:
            rebuilt, extra_removed = _strip_segment_command(raw, cmd, little)
            removed_ranges.extend(extra_removed)
            if rebuilt is None:
                offset += cmdsize
                continue
            kept.append(rebuilt)
            offset += cmdsize
            continue
        kept.append(raw)
        offset += cmdsize
    new_cmds = b"".join(kept)
    if len(new_cmds) > sizeofcmds:
        raise ArchiveError("sanitized load commands overflow the original command region")
    out = bytearray(content)
    out[16:20] = _pack32(len(kept), little)
    out[header_size : header_size + sizeofcmds] = new_cmds + bytes(sizeofcmds - len(new_cmds))
    trailing_only = all(
        size <= 0 or fileoff + size >= len(out) or fileoff + size == len(content)
        for fileoff, size in removed_ranges
    )
    if removed_ranges and not trailing_only:
        kept = [_adjust_known_command(raw, _u32(raw, 0, little), little, removed_ranges) for raw in kept]
        new_cmds = b"".join(kept)
        if len(new_cmds) > sizeofcmds:
            raise ArchiveError("adjusted load commands overflow the original command region")
        out[header_size : header_size + sizeofcmds] = new_cmds + bytes(sizeofcmds - len(new_cmds))
        for fileoff, size in sorted(removed_ranges, reverse=True):
            if size > 0:
                del out[fileoff : fileoff + size]
    else:
        for fileoff, size in sorted(removed_ranges, reverse=True):
            if size > 0 and fileoff + size <= len(out):
                del out[fileoff : fileoff + size]
    return bytes(out)


def _strip_fat_macho(content: bytes) -> bytes:
    magic = struct.unpack_from(">I", content, 0)[0]
    little = False
    if magic not in {0xCAFEBABE, 0xCAFEBABF}:
        magic = struct.unpack_from("<I", content, 0)[0]
        little = True
        if magic not in {0xCAFEBABE, 0xCAFEBABF}:
            raise ArchiveError("not a Mach-O FAT archive")
    is_64 = magic == 0xCAFEBABF
    nfat = _u32(content, 4, little)
    header_size = 8
    arch_size = 32 if is_64 else 20
    slices = []
    for index in range(nfat):
        entry = header_size + index * arch_size
        if is_64:
            offset = _u64(content, entry + 8, little)
            size = _u64(content, entry + 16, little)
        else:
            offset = _u32(content, entry + 8, little)
            size = _u32(content, entry + 12, little)
        slices.append((entry, content[offset : offset + size]))
    rebuilt = [strip_macho_bitcode(blob) for _, blob in slices]
    # Keep original alignment by rewriting each slice in place when it shrank
    # only by trailing bitcode; fail if a slice grew.
    out = bytearray(content)
    for (entry, original), stripped in zip(slices, rebuilt):
        if len(stripped) > len(original):
            raise ArchiveError("sanitized FAT slice grew")
        offset = _u64(content, entry + 8, little) if is_64 else _u32(content, entry + 8, little)
        out[offset : offset + len(stripped)] = stripped
        if len(stripped) < len(original):
            out[offset + len(stripped) : offset + len(original)] = bytes(len(original) - len(stripped))
            if is_64:
                out[entry + 16 : entry + 24] = _pack64(len(stripped), little)
            else:
                out[entry + 12 : entry + 16] = _pack32(len(stripped), little)
    return bytes(out)


def strip_macho_bitcode(content: bytes) -> bytes:
    if len(content) < 8:
        raise ArchiveError("truncated object while removing bitcode")
    magic = struct.unpack_from("<I", content, 0)[0]
    if magic in {0xCAFEBABE, 0xBEBAFECA}:
        return _strip_fat_macho(content)
    be_magic = struct.unpack_from(">I", content, 0)[0]
    if magic not in MACHO_MAGICS and be_magic not in MACHO_MAGICS:
        raise ArchiveError("cannot strip bitcode from a non-Mach-O member")
    return _strip_thin_macho(content)


def sanitize_member(name: str, content: bytes) -> bytes:
    if not member_has_bitcode(content):
        return content
    if content.startswith(LLVM_BITCODE_MAGIC) or content.startswith(LLVM_WRAPPER_MAGIC):
        raise ArchiveError(
            f"member {name} is raw LLVM bitcode, not a native Mach-O object"
        )
    stripped = strip_macho_bitcode(content)
    if member_has_bitcode(stripped):
        raise ArchiveError(f"member {name} still contains LLVM bitcode after sanitization")
    return stripped


def write_archive(path: Path, members: list[tuple[str, bytes]]) -> None:
    blob = bytearray(AR_MAGIC)
    for name, content in members:
        encoded = name.encode("ascii")
        if len(encoded) > 15:
            stored = encoded + b"\0"
            payload = stored + content
            name_field = f"#1/{len(stored)}".encode().ljust(16)
        else:
            payload = content
            name_field = encoded.ljust(16)
        header = (
            name_field
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"644".ljust(8)
            + f"{len(payload)}".encode().rjust(10)
            + b"`\n"
        )
        blob.extend(header)
        blob.extend(payload)
        if len(payload) % 2 == 1:
            blob.append(0)
    path.write_bytes(blob)


def sanitize_archive(path: Path) -> int:
    members = [(name, content) for _, name, content in iter_ar_members(path.read_bytes())]
    if not members:
        raise ArchiveError(f"{path} contains no archive members")
    sanitized = [(name, sanitize_member(name, content)) for name, content in members]
    write_archive(path, sanitized)
    return check_archive(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--otool-output", type=Path)
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Remove leftover Mach-O __LLVM / __bitcode segments and MH_OBJECT sections",
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    os.umask(0o077)
    extra = args.otool_output.read_text() if args.otool_output else None
    try:
        if args.sanitize:
            if extra is not None:
                raise ArchiveError("--otool-output cannot be combined with --sanitize")
            count = sanitize_archive(args.archive)
            print(f"Sanitized {count} native archive member(s) in {args.archive}")
            return 0
        count = check_archive(args.archive, extra)
    except ArchiveError as error:
        sys.stderr.write(f"error: {error}\n")
        return 1
    print(f"Validated {count} native archive member(s) in {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
