#!/usr/bin/env python3
"""Real Apple archive reconstruction and link regression, not synthetic Mach-O."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("archive", Path(__file__).with_name("release-profile-archive.py"))
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)


@unittest.skipUnless(sys.platform == "darwin", "requires Apple toolchain")
class NativeArchiveTests(unittest.TestCase):
    def setUp(self):
        # Host executables must not inherit an iOS workflow deployment target.
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("IPHONEOS_DEPLOYMENT_TARGET", "TVOS_DEPLOYMENT_TARGET",
                     "WATCHOS_DEPLOYMENT_TARGET", "XROS_DEPLOYMENT_TARGET", "SDKROOT"):
            os.environ.pop(name, None)

    def test_sanitized_embedded_bitcode_object_still_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "native.c"
            source.write_text("int native_symbol(void) { return 42; }\n")
            obj = root / "native.o"
            subprocess.run(["xcrun", "clang", "-fembed-bitcode", "-c", str(source), "-o", str(obj)], check=True)
            self.assertTrue(archive.member_has_bitcode(obj.read_bytes()))
            library = root / "native.a"
            subprocess.run(["xcrun", "libtool", "-static", "-o", str(library), str(obj)], check=True)
            original = library.read_bytes()
            with patch.object(archive, "check_archive", side_effect=archive.ArchiveError("injected validation failure")):
                with self.assertRaises(archive.ArchiveError):
                    archive.sanitize_archive(library)
            self.assertEqual(library.read_bytes(), original)
            archive.sanitize_archive(library)
            archive.check_archive(library)
            main = root / "main.c"
            main.write_text("int native_symbol(void); int main(void) { return native_symbol()!=42; }\n")
            executable = root / "probe"
            subprocess.run(["xcrun", "clang", str(main), str(library), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)

    def test_rebuild_regenerates_index_and_preserves_duplicate_names_and_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for index in range(2):
                folder = root / str(index)
                folder.mkdir()
                source = folder / "same.c"
                source.write_text(f"int symbol_{index}(void) {{ return {index + 1}; }}\n")
                obj = folder / "same.o"
                subprocess.run(["xcrun", "clang", "-c", str(source), "-o", str(obj)], check=True)
                objects.append(obj)
            library = root / "original.a"
            subprocess.run(["xcrun", "libtool", "-static", "-o", str(library), *map(str, objects)], check=True)
            members = [(name, data) for _, name, data in archive.iter_ar_members(library.read_bytes())]
            original_bytes = library.read_bytes()
            with patch.object(archive, "write_archive", side_effect=AssertionError("native archive must not be rebuilt")):
                archive.sanitize_archive(library)
            self.assertEqual(library.read_bytes(), original_bytes)
            with patch.object(archive, "check_archive", side_effect=archive.ArchiveError("injected native validation failure")):
                with self.assertRaises(archive.ArchiveError):
                    archive.sanitize_archive(library)
            self.assertEqual(library.read_bytes(), original_bytes)
            rebuilt = root / "rebuilt.a"
            archive.write_archive(rebuilt, members)
            subprocess.run(["xcrun", "otool", "-l", str(rebuilt)], check=True, capture_output=True)
            self.assertEqual(sum(name == "same.o" for _, name, _ in archive.iter_ar_members(rebuilt.read_bytes())), 2)
            main = root / "main.c"
            main.write_text("int symbol_0(void); int symbol_1(void); int main(void) { return symbol_0()+symbol_1()!=3; }\n")
            executable = root / "probe"
            subprocess.run(["xcrun", "clang", str(main), str(rebuilt), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
