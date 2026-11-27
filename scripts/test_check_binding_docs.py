#!/usr/bin/env python3
"""Regression tests for binding reference generation and release documentation."""
from pathlib import Path
import tempfile
import unittest

from check_binding_docs import (
    Export, c_exports_in, release_problems, render, uniffi_exports_in,
)


class BindingDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = "Marmot::start"
        self.export = Export("pub async fn start(&self) -> Result<(), Error>", "src/lib.rs#L10")
        self.expected = {self.key: self.export}
        self.text = "### `Marmot::start`\n\nStart account work.\n"

    def test_rejects_omitted_method(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing method: Marmot::start"):
            render("# Guide\n", "rust", self.expected)

    def test_rejects_removed_method(self) -> None:
        with self.assertRaisesRegex(ValueError, "removed/unknown method: Marmot::start"):
            render(self.text, "rust", {})

    def test_rejects_duplicate_entries(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate documented method: Marmot::start"):
            render(self.text + self.text, "rust", self.expected)

    def test_does_not_count_next_section_as_guidance(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing authored guidance: Marmot::start"):
            render("### `Marmot::start`\n\n## Unrelated\n\nSome text.\n", "rust", self.expected)

    def test_rejects_generated_docs(self) -> None:
        guide = self.text + "\n```rust\npub fn begin(&self)\n```\n"
        for text in (guide, self.text + "\n[Source](src/lib.rs#L8)\n"):
            with self.assertRaisesRegex(ValueError, "generated signature or source link in guide"):
                render(text, "rust", self.expected)
        c = {"marmot_start": Export("MarmotStatus marmot_start(void);", "include/marmot.h#L1")}
        with self.assertRaisesRegex(ValueError, "generated signature or source link in guide"):
            render("### `marmot_start`\n\nStart runtime.\n\n```c\nint marmot_begin(void);\n```\n", "c", c)
        example = self.text + "\n```rust\nlet outcome = marmot.start().await;\n```\n"
        self.assertIn(example.split("\n\n", 1)[1], render(example, "rust", self.expected))

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

    def test_source_shift_updates_reference_without_editing_guide(self) -> None:
        source = "#[uniffi::export]\nimpl Marmot {\n    pub fn get(&self) -> bool { true }\n}\n"
        guide = "### `Marmot::get`\n\nRead the current value.\n"
        old = render(guide, "rust", uniffi_exports_in(source, "lib.rs"))
        new = render(guide, "rust", uniffi_exports_in("// comment\n" + source, "lib.rs"))
        self.assertIn("[Source](src/lib.rs#L3)", old)
        self.assertEqual(new, old.replace("#L3", "#L4"))
        self.assertIn("\n\nRead the current value.\n", new)

    def test_unsupported_export_and_unrecognized_methods_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported UniFFI export shape"):
            uniffi_exports_in("#[uniffi::export]\nexport_macro!();", "lib.rs")
        with self.assertRaisesRegex(ValueError, "no exported methods"):
            uniffi_exports_in("#[uniffi::export]\nimpl Marmot { methods!(); }", "lib.rs")

    def test_c_reference_links_to_declaration_after_multiline_comment(self) -> None:
        source = "/* intro\n * doc */\nMarmotStatus marmot_start(\n  const struct MarmotClient *client);\n"
        text = render("### `marmot_start`\n\nStart runtime.\n", "c", c_exports_in(source))
        self.assertIn("```c\nMarmotStatus marmot_start( const struct MarmotClient *client);\n```", text)
        self.assertIn("[Header contract](include/marmot.h#L3)", text)


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
