#!/usr/bin/env python3
"""Regression tests for reference refresh, drift rejection and release documentation."""
from pathlib import Path
import tempfile
import unittest

from check_binding_docs import (
    Export, NEEDS_PROSE, REPO, c_exports_in, check, refresh, release_problems,
    scaffold, uniffi_catalog, uniffi_exports_in,
)


class BindingDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = "Marmot::start"
        self.export = Export("pub async fn start(&self) -> Result<(), Error>", "src/lib.rs#L10")
        self.expected = {self.key: self.export}
        self.text = scaffold(self.key, self.export, "rust").replace(NEEDS_PROSE, "**Current.** Start account work.\n\nKeep this authored guidance.")

    def test_repository_references_match_source_and_links(self) -> None:
        self.assertEqual(check((REPO / "crates/marmot-uniffi/API-REFERENCE.md").read_text(), "rust", uniffi_catalog()), [])
        self.assertEqual(check((REPO / "crates/marmot-c/API-REFERENCE.md").read_text(), "c", c_exports_in((REPO / "crates/marmot-c/include/marmot.h").read_text())), [])

    def test_rejects_omitted_method(self) -> None:
        self.assertIn("missing method", "\n".join(check("", "rust", self.expected)))

    def test_rejects_removed_method_without_deleting_guidance(self) -> None:
        self.assertIn("removed/unknown", "\n".join(check(self.text, "rust", {})))
        self.assertEqual(refresh(self.text, "rust", {}), self.text)

    def test_rejects_duplicate_entries_and_refuses_write(self) -> None:
        text = self.text + self.text
        self.assertIn("duplicate", "\n".join(check(text, "rust", self.expected)))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            refresh(text, "rust", self.expected)

    def test_signature_error_shows_actual_and_expected(self) -> None:
        text = self.text.replace("pub async fn", "pub fn")
        error = "\n".join(check(text, "rust", self.expected))
        self.assertIn("changed signature", error)
        self.assertIn("actual:   pub fn", error)
        self.assertIn("expected: pub async fn", error)

    def test_source_line_shift_fails_and_write_preserves_prose(self) -> None:
        stale = self.text.replace("#L10", "#L9").replace("pub async fn", "pub fn")
        self.assertIn("changed source link", "\n".join(check(stale, "rust", self.expected)))
        written = refresh(stale, "rust", self.expected)
        self.assertEqual(written, self.text)
        self.assertEqual(refresh(written, "rust", self.expected), written)
        self.assertEqual(check(written, "rust", self.expected), [])

    def test_new_export_scaffold_requires_editorial_work(self) -> None:
        text = refresh("# Reference\n", "rust", self.expected)
        self.assertIn("### `Marmot::start`", text)
        self.assertIn(self.export.signature, text)
        self.assertIn(self.export.source, text)
        self.assertEqual(check(text, "rust", self.expected), [f"missing authored guidance: {self.key}"])
        self.assertEqual(refresh(text, "rust", self.expected), text)

    def test_nested_indentation_and_free_function_names(self) -> None:
        source = """mod nested {
    #[uniffi::export]
    impl Marmot {
        pub async fn start(&self) -> Result<(), Error> { Ok(()) }
    }
    #[uniffi::export(with_foreign)]
    pub trait Signer {
        fn sign(&self, text: String) -> String;
    }
    #[uniffi::export]
    pub fn parse_tag(tag: String) -> String { tag }
}
"""
        exports = uniffi_exports_in(source, "nested.rs")
        self.assertEqual(set(exports), {"Marmot::start", "Signer::sign", "parse_tag"})
        for name, item in exports.items():
            line = int(item.source.split("#L")[1])
            self.assertIn("fn " + name.split("::")[-1] + "(", source.splitlines()[line - 1])

    def test_same_line_export_attribute_is_not_silently_skipped(self) -> None:
        exports = uniffi_exports_in("#[uniffi::export] pub fn parse_tag(tag: String) -> String { tag }", "lib.rs")
        self.assertEqual(set(exports), {"parse_tag"})
        with self.assertRaisesRegex(ValueError, "unsupported UniFFI export shape"):
            uniffi_exports_in("#[uniffi::export] export_macro!();", "lib.rs")

    def test_source_shift_updates_anchor_without_signature_change(self) -> None:
        source = "#[uniffi::export]\nimpl Marmot {\n    pub fn get(&self) -> bool { true }\n}\n"
        old = uniffi_exports_in(source, "lib.rs")["Marmot::get"]
        new = uniffi_exports_in("// comment\n" + source, "lib.rs")["Marmot::get"]
        self.assertEqual(old.signature, new.signature)
        self.assertEqual(old.source, "src/lib.rs#L3")
        self.assertEqual(new.source, "src/lib.rs#L4")

    def test_unsupported_export_and_unrecognized_methods_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported UniFFI export shape"):
            uniffi_exports_in("#[uniffi::export]\nexport_macro!();", "lib.rs")
        with self.assertRaisesRegex(ValueError, "no exported methods"):
            uniffi_exports_in("#[uniffi::export]\nimpl Marmot { methods!(); }", "lib.rs")

    def test_c_comment_offsets_and_signature_and_anchor_refresh(self) -> None:
        source = "/* intro\n * doc */\nMarmotStatus marmot_start(\n  const struct MarmotClient *client);\n"
        expected = c_exports_in(source)
        self.assertEqual(expected["marmot_start"].source, "include/marmot.h#L3")
        text = scaffold("marmot_start", expected["marmot_start"], "c").replace(NEEDS_PROSE, "Start runtime.")
        drifted = text.replace("const struct", "struct").replace("#L3", "#L2")
        self.assertEqual(len(check(drifted, "c", expected)), 2)
        self.assertEqual(refresh(drifted, "c", expected), text)


class ReleaseDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.10.2"\n')
        self.notes = self.root / "docs/release/0.10.2.md"
        self.guide = self.root / "docs/integration/0.10.2.md"
        self.notes.parent.mkdir(parents=True)
        self.guide.parent.mkdir(parents=True)
        self.notes.write_text("[Guide](../integration/0.10.2.md)\n")
        self.guide.write_text("[Notes](../release/0.10.2.md#highlights)\n")

    def test_reciprocal_release_documents_pass(self) -> None:
        self.assertEqual(release_problems(self.root, "0.10.2"), [])

    def test_missing_either_document_fails(self) -> None:
        for path in (self.notes, self.guide):
            with self.subTest(path=path):
                content = path.read_text()
                path.unlink()
                self.assertIn("missing release document", "\n".join(release_problems(self.root, "0.10.2")))
                path.write_text(content)

    def test_missing_or_example_only_link_fails_in_either_direction(self) -> None:
        for path in (self.notes, self.guide):
            for wrapper in ("no link", "```md\n{}\n```", "<!-- {} -->"):
                with self.subTest(path=path, wrapper=wrapper):
                    content = path.read_text()
                    path.write_text(wrapper.format(content))
                    self.assertIn("must link", "\n".join(release_problems(self.root, "0.10.2")))
                    path.write_text(content)

    def test_wrong_version_or_unsafe_path_is_rejected(self) -> None:
        self.assertIn("does not match workspace", "\n".join(release_problems(self.root, "0.10.3")))
        self.assertIn("invalid release version", "\n".join(release_problems(self.root, "../0.10.2")))

    def test_policy_does_not_require_guides_before_0102(self) -> None:
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.10.1"\n')
        self.assertEqual(release_problems(self.root, "0.10.1"), [])


if __name__ == "__main__":
    unittest.main()
