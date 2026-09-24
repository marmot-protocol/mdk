#!/usr/bin/env python3
"""Deterministic ELF and workflow-assembly regressions for Android 16 KB alignment."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import textwrap
import unittest
import zipfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VALIDATOR = HERE / "validate-android-artifact.py"
SIXTY_FOUR = {"arm64-v8a", "x86_64"}
TARGET_TO_ABI = {
    "aarch64-linux-android": "arm64-v8a",
    "armv7-linux-androideabi": "armeabi-v7a",
    "i686-linux-android": "x86",
    "x86_64-linux-android": "x86_64",
}
ABIS = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
MACHINES = {"arm64-v8a": 183, "armeabi-v7a": 40, "x86": 3, "x86_64": 62}
CLASSES = {"arm64-v8a": 64, "armeabi-v7a": 32, "x86": 32, "x86_64": 64}


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_android_artifact", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def library_for_target(triple, align=None):
    abi = TARGET_TO_ABI[triple]
    if align is None:
        align = 0x4000 if abi in SIXTY_FOUR else 0x1000
    return elf_with_alignments(abi, [align, align])


def elf_with_alignments(abi, alignments, **options):
    elf_class = options.get("elf_class", CLASSES[abi])
    machine = options.get("machine", MACHINES[abi])
    e_type = options.get("e_type", 3)
    payload = options.get("payload", b"marmot-android")
    endian_flag = options.get("endian", 1)
    ident_class = options.get("ident_class", 2 if elf_class == 64 else 1)
    ident_version = options.get("ident_version", 1)
    version = options.get("version", 1)
    ehsize = 64 if elf_class == 64 else 52
    phentsize = 56 if elf_class == 64 else 32
    segment_types = options.get("segment_types")
    if segment_types is None:
        segment_types = [1] * len(alignments)
    phnum = options.get("phnum", len(segment_types))
    phoff = ehsize
    header_bytes = ehsize if phnum == 0 else phoff + phnum * phentsize
    placements = []
    cursor = header_bytes
    for index, align in enumerate(alignments):
        if index == 0:
            offset = 0
            filesz = header_bytes
        else:
            offset = cursor if align <= 1 else (cursor + align - 1) & ~(align - 1)
            filesz = len(payload)
            cursor = offset + filesz
        vaddr = offset
        if options.get("incongruent_index") == index:
            vaddr = offset + 1
        declared_filesz = filesz + options.get("extra_filesz", 0) if options.get("inflate_index") == index else filesz
        memsz = declared_filesz
        if options.get("shrink_memsz_index") == index and declared_filesz:
            memsz = declared_filesz - 1
        placements.append((segment_types[index], offset, vaddr, declared_filesz, memsz, align))
    file_size = header_bytes
    for _typ, offset, _vaddr, filesz, _memsz, _align in placements:
        if options.get("inflate_index") is None:
            file_size = max(file_size, offset + filesz)
        else:
            real_filesz = len(payload) if offset else header_bytes
            file_size = max(file_size, offset + real_filesz)
    blob = bytearray(file_size)
    if payload and len(placements) > 1:
        start = placements[1][1]
        blob[start:start + len(payload)] = payload
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = ident_class
    ident[5] = endian_flag
    ident[6] = ident_version
    if elf_class == 64:
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            bytes(ident), e_type, machine, version, 0, phoff, 0, 0, 64, 56, phnum, 0, 0, 0,
        )
    else:
        header = struct.pack(
            "<16sHHIIIIIHHHHHH",
            bytes(ident), e_type, machine, version, 0, phoff, 0, 0, 52, 32, phnum, 0, 0, 0,
        )
    blob[:len(header)] = header
    for index, (p_type, offset, vaddr, filesz, memsz, align) in enumerate(placements):
        start = phoff + index * phentsize
        if elf_class == 64:
            blob[start:start + 56] = struct.pack("<IIQQQQQQ", p_type, 5, offset, vaddr, vaddr, filesz, memsz, align)
        else:
            blob[start:start + 32] = struct.pack("<IIIIIIII", p_type, offset, vaddr, vaddr, filesz, memsz, 5, align)
    if options.get("truncate") is not None:
        return bytes(blob[:options["truncate"]])
    return bytes(blob)


def good_libraries():
    libraries = {}
    for abi in ABIS:
        align = 0x4000 if abi in SIXTY_FOUR else 0x1000
        libraries[abi] = elf_with_alignments(abi, [align, align])
    return libraries


def run_validator(*args):
    return subprocess.run(
        ["python3", str(VALIDATOR), *args],
        capture_output=True,
        text=True,
    )


def write_support(root):
    files = {
        "kotlin/dev/ipf/marmotkit/marmot_uniffi.kt": "fun generated() {}\n",
        "kotlin/dev/ipf/marmotkit/MarmotAndroid.kt": "class MarmotAndroid\n",
        "kotlin/io/crates/keyring/Keyring.kt": "class Keyring\n",
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def write_libraries(root, libraries):
    for abi, data in libraries.items():
        path = root / "jniLibs" / abi / "libmarmot_uniffi.so"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def make_bundle(root, libraries):
    write_support(root)
    write_libraries(root, libraries)


class AndroidArtifactTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator()

    def assert_rejects(self, data, abi, text):
        result = self.validate_bytes(data, abi)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn(text, result.stderr)

    def validate_bytes(self, data, abi):
        directory = Path(self.id().replace(".", "_"))
        # Keep fixtures under the assigned temporary directory.
        root = Path(os.environ.get("TMPDIR", "/tmp")) / "android-elf-tests" / directory.name
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{abi}.so"
        path.write_bytes(data)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return run_validator("library", "--abi", abi, str(path))

    def test_sixty_four_bit_alignment_matrix(self):
        cases = (
            ("arm64-v8a", [0x1000, 0x1000], False),
            ("arm64-v8a", [0x4000, 0x4000], True),
            ("arm64-v8a", [0x4000, 0x1000], False),
            ("arm64-v8a", [0x10000, 0x10000], True),
            ("x86_64", [0x1000, 0x1000], False),
            ("x86_64", [0x4000, 0x4000], True),
            ("x86_64", [0x4000, 0x1000], False),
            ("x86_64", [0x8000, 0x8000], True),
        )
        for abi, alignments, accept in cases:
            with self.subTest(abi=abi, alignments=alignments):
                data = elf_with_alignments(abi, alignments)
                result = self.validate_bytes(data, abi)
                self.assertEqual(result.returncode == 0, accept, result.stderr)

    def test_invalid_alignment_and_congruence_reject(self):
        for abi in ("arm64-v8a", "x86_64"):
            with self.subTest(abi=abi, case="zero"):
                self.assert_rejects(elf_with_alignments(abi, [0, 0]), abi, "power of two")
            with self.subTest(abi=abi, case="one"):
                self.assert_rejects(elf_with_alignments(abi, [1, 1]), abi, "below 16 KB")
            with self.subTest(abi=abi, case="odd"):
                self.assert_rejects(elf_with_alignments(abi, [0x3000, 0x3000]), abi, "power of two")
            with self.subTest(abi=abi, case="incongruent"):
                data = elf_with_alignments(abi, [0x4000, 0x4000], incongruent_index=1)
                self.assert_rejects(data, abi, "not congruent")

    def test_malformed_elf_rejects(self):
        abi = "arm64-v8a"
        valid = elf_with_alignments(abi, [0x4000, 0x4000])
        cases = {
            "empty": (b"", "not an ELF"),
            "text": (b"not an elf", "not an ELF"),
            "truncated-header": (valid[:20], "truncated ELF header"),
            "truncated-table": (elf_with_alignments(abi, [0x4000, 0x4000], truncate=70), "truncated"),
            "wrong-machine": (elf_with_alignments(abi, [0x4000], machine=62), "unexpected ELF machine"),
            "wrong-class": (elf_with_alignments(abi, [0x1000], elf_class=32, ident_class=1), "unexpected ELF class"),
            "big-endian": (elf_with_alignments(abi, [0x4000], endian=2), "unsupported ELF encoding"),
            "unknown-class": (elf_with_alignments(abi, [0x4000], ident_class=3), "unsupported ELF encoding"),
            "executable": (elf_with_alignments(abi, [0x4000, 0x4000], e_type=2), "not a shared object"),
            "no-load": (elf_with_alignments(abi, [0x1000], segment_types=[0]), "no load segments"),
            "zero-phnum": (elf_with_alignments(abi, [], phnum=0), "invalid program header count"),
            "memsz": (elf_with_alignments(abi, [0x4000, 0x4000], shrink_memsz_index=0), "exceeds memory size"),
            "past-eof": (elf_with_alignments(abi, [0x4000], inflate_index=0, extra_filesz=50), "past end of file"),
        }
        for name, (data, text) in cases.items():
            with self.subTest(name=name):
                self.assert_rejects(data, abi, text)
        thirty_two = elf_with_alignments("armeabi-v7a", [0x1000, 0x1000])
        result = self.validate_bytes(thirty_two, "armeabi-v7a")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.validate_bytes(thirty_two, "x86")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_encoding_does_not_accept_empty_segments(self):
        data = bytearray(elf_with_alignments("arm64-v8a", [0x4000, 0x4000]))
        data[4] = 3
        result = self.validate_bytes(bytes(data), "arm64-v8a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported ELF encoding", result.stderr)
        self.assertNotIn("no load segments", result.stderr)

    def test_directory_and_bundle_round_trip(self):
        root = self.fresh("bundle")
        libraries = good_libraries()
        make_bundle(root, libraries)
        report = root / "android-elf.json"
        created = run_validator("directory", str(root), "--report", str(report))
        self.assertEqual(created.returncode, 0, created.stderr)
        parsed = json.loads(report.read_text())
        self.assertEqual(parsed["schema_version"], 1)
        self.assertEqual(parsed["minimum_64bit_load_alignment"], 16384)
        for abi in ABIS:
            entry = parsed["libraries"][f"jniLibs/{abi}/libmarmot_uniffi.so"]
            self.assertEqual(entry["abi"], abi)
            self.assertEqual(entry["elf_class"], CLASSES[abi])
            self.assertEqual(entry["machine"], MACHINES[abi])
            self.assertEqual(entry["sha256"], hashlib.sha256(libraries[abi]).hexdigest())
            minimum = 16384 if abi in SIXTY_FOUR else 4096
            self.assertTrue(all(align >= minimum for align in entry["load_alignments"]))
            self.assertGreaterEqual(len(entry["load_alignments"]), 2)
        archive = root.parent / "marmotkit.zip"
        root_name = root.name
        with zipfile.ZipFile(archive, "w") as handle:
            for path in root.rglob("*"):
                if path.is_file():
                    handle.write(path, f"{root_name}/{path.relative_to(root).as_posix()}")
        checked = run_validator(
            "bundle", str(archive), "--root", root_name, "--report", str(report)
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_final_zip_rejects_tampering_after_directory_validation(self):
        root = self.fresh("tamper")
        make_bundle(root, good_libraries())
        report = root / "android-elf.json"
        self.assertEqual(run_validator("directory", str(root), "--report", str(report)).returncode, 0)
        original = report.read_bytes()
        library = root / "jniLibs/arm64-v8a/libmarmot_uniffi.so"
        library.write_bytes(elf_with_alignments("arm64-v8a", [0x4000, 0x4000], payload=b"substituted"))
        archive = self.zip_tree(root)
        result = run_validator("bundle", str(archive), "--root", root.name, "--report", str(report))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assertEqual(report.read_bytes(), original)

    def test_bundle_rejects_unsafe_duplicate_and_bad_reports(self):
        root = self.fresh("zip-cases")
        make_bundle(root, good_libraries())
        report = root / "android-elf.json"
        self.assertEqual(run_validator("directory", str(root), "--report", str(report)).returncode, 0)
        good = self.zip_tree(root, label="good")
        self.assertEqual(
            run_validator("bundle", str(good), "--root", root.name, "--report", str(report)).returncode,
            0,
        )

        extra_library = root.parent / "extra-library.zip"
        extra_library.write_bytes(good.read_bytes())
        with zipfile.ZipFile(extra_library, "a") as handle:
            handle.writestr(f"{root.name}/jniLibs/other/libmarmot_uniffi.so", b"rogue")
        self.assertIn("unexpected archive library", run_validator(
            "bundle", str(extra_library), "--root", root.name, "--report", str(report)
        ).stderr)

        outside_root = root.parent / "outside-root.zip"
        outside_root.write_bytes(good.read_bytes())
        with zipfile.ZipFile(outside_root, "a") as handle:
            handle.writestr("other/manifest.txt", b"extra")
        self.assertIn("outside bundle root", run_validator(
            "bundle", str(outside_root), "--root", root.name, "--report", str(report)
        ).stderr)

        extra_corrupt = root.parent / "extra-corrupt.zip"
        extra_corrupt.write_bytes(good.read_bytes())
        with zipfile.ZipFile(extra_corrupt, "a") as handle:
            handle.writestr(f"{root.name}/manifest.txt", b"corrupt-me-unique")
        extra_corrupt.write_bytes(extra_corrupt.read_bytes().replace(b"corrupt-me-unique", b"corrupt-me-UNIQUE"))
        self.assertIn("corrupt archive", run_validator(
            "bundle", str(extra_corrupt), "--root", root.name, "--report", str(report)
        ).stderr)

        missing = self.zip_tree(root, skip={"android-elf.json"}, label="missing-report")
        self.assertIn("missing embedded report", run_validator(
            "bundle", str(missing), "--root", root.name, "--report", str(report)
        ).stderr)

        malformed = self.zip_tree(root, replace={"android-elf.json": b"{"}, label="malformed")
        self.assertIn("malformed report", run_validator(
            "bundle", str(malformed), "--root", root.name, "--report", str(report)
        ).stderr)

        lied = json.loads(report.read_text())
        lied["libraries"]["jniLibs/arm64-v8a/libmarmot_uniffi.so"]["sha256"] = "0" * 64
        mismatched = self.zip_tree(
            root, replace={"android-elf.json": json.dumps(lied).encode()}, label="mismatched"
        )
        self.assertIn("embedded report", run_validator(
            "bundle", str(mismatched), "--root", root.name, "--report", str(report)
        ).stderr)

        staged = report.read_text()
        report.write_text(json.dumps(lied))
        disagreed = run_validator("bundle", str(good), "--root", root.name, "--report", str(report))
        self.assertIn("staged report", disagreed.stderr)
        report.write_text(staged)

        duplicate = root.parent / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as handle:
            payload = (root / "jniLibs/x86/libmarmot_uniffi.so").read_bytes()
            name = f"{root.name}/jniLibs/x86/libmarmot_uniffi.so"
            handle.writestr(name, payload)
            handle.writestr(name, payload)
        self.assertIn("duplicate", run_validator(
            "bundle", str(duplicate), "--root", root.name, "--report", str(report)
        ).stderr)

        unsafe = root.parent / "unsafe.zip"
        with zipfile.ZipFile(unsafe, "w") as handle:
            handle.writestr(f"{root.name}/../escape.so", b"nope")
        self.assertIn("unsafe", run_validator(
            "bundle", str(unsafe), "--root", root.name, "--report", str(report)
        ).stderr)

        linked = root.parent / "link.zip"
        info = zipfile.ZipInfo(f"{root.name}/jniLibs/arm64-v8a/libmarmot_uniffi.so")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        info.file_size = 3
        with zipfile.ZipFile(linked, "w") as handle:
            handle.writestr(info, b"abc")
        self.assertIn("non-regular", run_validator(
            "bundle", str(linked), "--root", root.name, "--report", str(report)
        ).stderr)

        corrupt = root.parent / "corrupt.zip"
        corrupt.write_bytes(good.read_bytes()[:30])
        self.assertIn("corrupt", run_validator(
            "bundle", str(corrupt), "--root", root.name, "--report", str(report)
        ).stderr)

        absent = self.fresh("missing-lib")
        libraries = good_libraries()
        del libraries["x86_64"]
        make_bundle(absent, libraries)
        self.assertNotEqual(run_validator("directory", str(absent), "--report", str(absent / "android-elf.json")).returncode, 0)

    def test_release_and_candidate_assembly_commands(self):
        release = (ROOT / ".github/workflows/bindings.yaml").read_text()
        candidate = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        self.assertGreaterEqual(candidate.count("- .github/workflows/bindings.yaml"), 2)
        self.assertIn("test-android-artifact.py", candidate)
        release_script = extract_run(release, "      - name: Package Android bundle\n")
        candidate_script = extract_run(candidate, "      - name: Assemble and validate Android candidate package\n")
        self.assertIn("validate-android-artifact.py directory", release_script)
        self.assertIn("validate-android-artifact.py bundle", release_script)
        self.assertIn("validate-android-artifact.py directory", candidate_script)
        self.assertIn("validate-android-artifact.py bundle", candidate_script)
        self.assertIn('--artifact-root packaged-source/crates/marmot-uniffi/output/android', release)
        self.assertIn("--artifact-root crates/marmot-uniffi/output/android", candidate)

        tools = self.fresh("tools")
        write_executable(tools / "jq", JQ_SHIM)
        write_executable(tools / "zip", ZIP_SHIM)
        env = os.environ.copy()
        env["PATH"] = f"{tools}:{env['PATH']}"

        accepted = good_libraries()
        rejected = dict(accepted)
        rejected["arm64-v8a"] = elf_with_alignments("arm64-v8a", [0x1000, 0x1000])
        missing = dict(accepted)
        del missing["x86_64"]

        release_ok = self.assemble_release(release_script, env, accepted)
        self.assertEqual(release_ok.returncode, 0, release_ok.stdout + release_ok.stderr)
        self.assertTrue(any((release_ok.directory / "dist").glob("*.zip.sha256")))
        archive = next((release_ok.directory / "dist").glob("*.zip"))
        report = json.loads(unzip_text(archive, "marmotkit-android-0.10.4/android-elf.json"))
        manifest = json.loads(unzip_text(archive, "marmotkit-android-0.10.4/manifest.json"))
        self.assertEqual(manifest["elf_validation"], "android-elf.json")
        self.assertEqual(manifest["contents"], [
            "kotlin/dev/ipf/marmotkit/marmot_uniffi.kt",
            "jniLibs/arm64-v8a/libmarmot_uniffi.so",
            "jniLibs/armeabi-v7a/libmarmot_uniffi.so",
            "jniLibs/x86/libmarmot_uniffi.so",
            "jniLibs/x86_64/libmarmot_uniffi.so",
        ])
        self.assertTrue(all(min(entry["load_alignments"]) >= 16384
                            for key, entry in report["libraries"].items() if "arm64" in key or "x86_64" in key))

        release_bad = self.assemble_release(release_script, env, rejected)
        self.assertNotEqual(release_bad.returncode, 0, release_bad.stdout + release_bad.stderr)
        self.assertEqual(list((release_bad.directory / "dist").glob("*.sha256")), [])
        release_missing = self.assemble_release(release_script, env, missing)
        self.assertNotEqual(release_missing.returncode, 0)

        candidate_ok = self.assemble_candidate(candidate_script, env, accepted)
        self.assertEqual(candidate_ok.returncode, 0, candidate_ok.stdout + candidate_ok.stderr)
        packaged = candidate_ok.directory / "runner/marmotkit-profile-android"
        self.assertTrue((packaged / ("a" * 40 + ".zip.sha256")).is_file())
        candidate_report = json.loads(unzip_text(
            packaged / ("a" * 40 + ".zip"),
            f"marmotkit-android-{'a' * 40}/android-elf.json",
        ))
        self.assertEqual(candidate_report["schema_version"], 1)
        candidate_bad = self.assemble_candidate(candidate_script, env, rejected)
        self.assertNotEqual(candidate_bad.returncode, 0)
        self.assertEqual(list((candidate_bad.directory / "runner/marmotkit-profile-android").glob("*.sha256")), [])
        candidate_missing = self.assemble_candidate(candidate_script, env, missing)
        self.assertNotEqual(candidate_missing.returncode, 0)

    def assemble_release(self, script, env, libraries):
        root = self.fresh("release")
        output = root / "packaged-source/crates/marmot-uniffi/output/android"
        make_bundle(output, libraries)
        (root / "packaged-source/Cargo.toml").write_text('version = "0.10.4"\n')
        (root / "packaged-source/Cargo.lock").write_text("lockfile\n")
        link_validator(root)
        (root / "runner").mkdir()
        completed = subprocess.run(["bash", "-c", script], cwd=root, env=env | {
            "RELEASE_ID": "0.10.4",
            "RELEASE_TAG": "marmotkit-v0.10.4",
            "SOURCE_SHA": "a" * 40,
            "BUILDER_SHA": "b" * 40,
            "MARMOTKIT_BUILD_RUSTC": "rustc fixture",
            "MARMOTKIT_BUILD_CARGO": "cargo fixture",
            "MARMOTKIT_BUILD_ANDROID_NDK_HOME": "/ndk",
            "MARMOTKIT_BUILD_ANDROID_NDK_VERSION": "27.2.12479018",
            "MARMOTKIT_BUILD_ANDROID_API": "26",
            "RUNNER_TEMP": str(root / "runner"),
        }, capture_output=True, text=True)
        completed.directory = root
        return completed

    def assemble_candidate(self, script, env, libraries):
        root = self.fresh("candidate")
        output = root / "crates/marmot-uniffi/output/android"
        make_bundle(output, libraries)
        provenance = output / "provenance"
        provenance.mkdir()
        (provenance / "arm64-v8a.json").write_text("{}\n")
        link_validator(root)
        (root / "runner").mkdir()
        completed = subprocess.run(["bash", "-c", script], cwd=root, env=env | {
            "SOURCE_SHA": "a" * 40,
            "BUILDER_SHA": "b" * 40,
            "GITHUB_RUN_ID": "12345",
            "RUNNER_TEMP": str(root / "runner"),
        }, capture_output=True, text=True)
        completed.directory = root
        return completed

    def fresh(self, name):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / "android-elf-tests" / f"{name}-{self._testMethodName}"
        if root.exists():
            import shutil
            shutil.rmtree(root)
        root.mkdir(parents=True)
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return root

    def zip_tree(self, root, skip=(), replace=None, label="packed"):
        replace = replace or {}
        archive = root.parent / f"{root.name}-{label}.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                if relative in skip:
                    continue
                data = replace.get(relative, path.read_bytes())
                handle.writestr(f"{root.name}/{relative}", data)
        return archive


def extract_run(workflow, step_name):
    block = workflow.split(step_name, 1)[1]
    block = block.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    return textwrap.dedent(block)


def link_validator(root):
    destination = root / "crates/marmot-uniffi/validate-android-artifact.py"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.symlink_to(VALIDATOR)


def write_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


def unzip_text(archive, member):
    completed = subprocess.run(["unzip", "-p", str(archive), member], capture_output=True, check=True)
    return completed.stdout.decode()


JQ_SHIM = r'''#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
exit_code = False
raw = False
while args and args[0].startswith("-"):
    flag = args.pop(0)
    exit_code = exit_code or "e" in flag
    raw = raw or "r" in flag
filter_text = args[0] if args else ""
document = json.load(sys.stdin)
if filter_text == ".contents[]":
    for item in document["contents"]:
        print(item)
    sys.exit(0)
if filter_text == ".elf_validation":
    value = document.get("elf_validation")
    print(value if isinstance(value, str) else "null")
    sys.exit(0)
if ".contents" in filter_text and "type ==" in filter_text:
    contents = document.get("contents")
    ok = (
        isinstance(contents, list)
        and len(contents) > 0
        and all(isinstance(item, str) and item for item in contents)
    )
    print("true" if ok else "false")
    sys.exit(0 if ok or not exit_code else 1)
sys.exit("unsupported jq filter")
'''


ZIP_SHIM = r'''#!/usr/bin/env python3
import sys, zipfile
from pathlib import Path
args = sys.argv[1:]
while args and args[0].startswith("-"):
    flag = args.pop(0)
    if flag.strip("-") and set(flag.strip("-")) <= set("qr"):
        continue
    sys.exit("unsupported zip flags")
destination = Path(args[0])
folder = Path(args[1])
destination.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(destination, "w") as archive:
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            archive.write(path, path.as_posix())
'''


if __name__ == "__main__":
    unittest.main()
