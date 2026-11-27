#!/usr/bin/env python3
"""Generate binding references from API guides and current Rust/C declarations."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import tomllib
from zipfile import BadZipFile, ZipFile

from check_c_binding_parity import REPO, UNIFFI_SRC, _braced_block, uniffi_exports

ENTRY = re.compile(r"^### `([^`]+)`\n(.*?)(?=^#{2,3} |^</details>|\Z)", re.MULTILINE | re.DOTALL)
GENERATED_LINK = re.compile(r"\[(?:Source|Header contract)\]\((?:src/|include/marmot\.h)[^)]*#L\d+\)")
DECLARATION_FENCE = re.compile(r"(?m)^```(c|rust)[ \t]*\n([^\n]+)\n```[ \t]*$")
DECLARATION = {
    "c": re.compile(r"(?!return\b)[A-Za-z_][\w \t*]*[ \t*]marmot_\w+\s*\([^;{}]*\);"),
    "rust": re.compile(r"(?:pub )?(?:async )?fn \w+\([^{}]*\)(?: -> [^{}]+)?;?"),
}


@dataclass(frozen=True)
class Export:
    """Mechanical metadata derived from one callable's source declaration."""
    signature: str
    source: str


def normalized(value: str) -> str:
    """Collapse signature whitespace to the reference's single-line representation."""
    return " ".join(value.split())


def uniffi_exports_in(text: str, source: str) -> dict[str, Export]:
    """Read exported impls, callback traits and functions regardless of indentation.

    As with the parity reader, declarations must be present as Rust source, not
    macro expansion. Unrecognized export shapes and empty method matches raise.
    """
    result: dict[str, Export] = {}
    for export in re.finditer(r"(?m)^[ \t]*#\[uniffi::export[^\]]*\]\s*", text):
        tail = text[export.end():]
        owner_match = re.match(r"\s*(impl|pub trait)\s+(\w+)[^{]*\{", tail)
        if owner_match:
            owner = owner_match[2]
            start = export.end() + tail.index("{")
            body = _braced_block(text, start)
            visibility = r"pub " if owner_match[1] == "impl" else ""
            methods = list(re.finditer(
                rf"(?m)^[ \t]*({visibility}(?:async )?fn (\w+)\s*\()", body))
            if not methods:
                raise ValueError(f"no exported methods recognized for {owner} in {source}")
        elif re.match(r"\s*pub (?:async )?fn ", tail):
            owner, body, start = None, tail, export.end()
            methods = [re.match(r"\s*(pub (?:async )?fn (\w+)\s*\()", body)]
        else:
            raise ValueError(f"unsupported UniFFI export shape in {source}")
        for method in methods:
            key = f"{owner}::{method[2]}" if owner else method[2]
            signature = re.split(r"\{|;", body[method.start(1):], maxsplit=1)[0]
            line = text[:start + method.start(1)].count("\n") + 1
            if key in result:
                raise ValueError(f"duplicate export {key}")
            result[key] = Export(normalized(signature), f"src/{source}#L{line}")
    return result


def uniffi_catalog() -> dict[str, Export]:
    """Collect each source export and cross-check the existing C-parity inventory."""
    result: dict[str, Export] = {}
    for path in sorted(UNIFFI_SRC.rglob("*.rs")):
        entries = uniffi_exports_in(path.read_text(), path.relative_to(UNIFFI_SRC).as_posix())
        if result.keys() & entries.keys():
            raise ValueError(f"duplicate exports across files: {result.keys() & entries.keys()}")
        result.update(entries)
    expected = {key if "::" in key else f"Marmot::{key}" for key in uniffi_exports()}
    if not expected <= result.keys():
        raise ValueError(f"missed parity exports: {sorted(expected - result.keys())}")
    return result


def c_exports_in(header: str) -> dict[str, Export]:
    """Extract header declarations while retaining comment line offsets for links."""
    clean = re.sub(r"/\*.*?\*/", lambda m: "\n" * m[0].count("\n"), header, flags=re.DOTALL)
    pattern = r"(?m)^([A-Za-z_][\w\s*]*?\b(marmot_\w+)\s*\([^;]*?\));"
    result: dict[str, Export] = {}
    for match in re.finditer(pattern, clean):
        key = match[2]
        if key in result:
            raise ValueError(f"duplicate C declaration: {key}")
        line = clean[:match.start()].count("\n") + 1
        result[key] = Export(normalized(match[1]) + ";", f"include/marmot.h#L{line}")
    names = set(re.findall(r"\b(marmot_\w+)\s*\(", clean))
    if names != result.keys():
        raise ValueError(f"unparsed C declarations: {sorted(names - result.keys())}")
    return result


def render(text: str, language: str, expected: dict[str, Export]) -> str:
    """Add signatures and links. Require exactly one authored entry per export."""
    seen: set[str] = set()
    errors: list[str] = []
    label = "Source" if language == "rust" else "Header contract"

    def replace(match: re.Match) -> str:
        key, body = match[1], match[2]
        if key in seen:
            errors.append(f"duplicate documented method: {key}")
        seen.add(key)
        if key not in expected:
            errors.append(f"removed/unknown method: {key}")
            return match[0]
        guidance = body.strip()
        if not guidance:
            errors.append(f"missing authored guidance: {key}")
        elif GENERATED_LINK.search(guidance) or any(
            DECLARATION[kind].fullmatch(line.strip())
            for kind, line in DECLARATION_FENCE.findall(guidance)
        ):
            errors.append(f"generated signature or source link in guide: {key}")
        export = expected[key]
        return (f"### `{key}`\n\n```{language}\n{export.signature}\n```\n\n"
                f"[{label}]({export.source})\n{body}")

    reference = ENTRY.sub(replace, text)
    errors.extend(f"missing method: {key}" for key in sorted(expected.keys() - seen))
    if errors:
        raise ValueError("\n".join(errors))
    return reference


def release_problems(root: Path, version: str) -> list[str]:
    """Check the confirmed workspace release has both documents and reciprocal links."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version)
    if not match:
        return [f"invalid release version: {version}"]
    workspace_version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if version != workspace_version:
        return [f"release version {version} does not match workspace {workspace_version}"]
    if tuple(int(n) for n in match.groups()) < (0, 10, 2):
        return []  # The companion-guide policy starts at 0.10.2.
    notes = root / "docs/release" / f"{version}.md"
    guide = root / "docs/integration" / f"{version}.md"
    errors = []
    for document, companion in [(notes, guide), (guide, notes)]:
        if not document.is_file():
            errors.append(f"missing release document: {document.relative_to(root)}")
            continue
        text = re.sub(r"```.*?```|<!--.*?-->", "", document.read_text(), flags=re.DOTALL)
        links = re.findall(r"\]\(([^)]+)\)", text)
        if not any((document.parent / link.split("#", 1)[0]).resolve() == companion.resolve()
                   for link in links if "://" not in link):
            errors.append(f"{document.relative_to(root)} must link to {companion.relative_to(root)}")
    return errors


def _check_c_bundle(path: Path) -> None:
    c = "references/marmot-c/API-REFERENCE.md"
    uniffi = "references/marmot-uniffi/API-REFERENCE.md"
    with ZipFile(path) as archive:
        root = f"marmot-c-{path.stem.removeprefix('marmot-c-linux-x86_64-')}"
        readme = archive.read(f"{root}/README.md").decode()
        reference = archive.read(f"{root}/{c}").decode()
        archive.getinfo(f"{root}/{uniffi}")
        header = archive.read(f"{root}/include/marmot.h").decode()

    for target in (c, uniffi):
        if not re.search(rf"\]\({re.escape(target)}(?:#[^)]*)?\)", readme):
            raise ValueError(f"bundled README does not link to {target}")
    if "](../../README.md)" not in reference:
        raise ValueError("bundled C reference does not link to the bundled README")

    links = {
        entry[1]: re.findall(r"\[Header contract\]\(([^)]+)\)", entry[2])
        for entry in ENTRY.finditer(reference)
    }
    for key, export in c_exports_in(header).items():
        if links.get(key) != [f"../../{export.source}"]:
            raise ValueError(f"bundled C reference has an invalid header link for {key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--with-c", action="store_true", help="also generate the C reference from the generated header")
    mode.add_argument("--c-bundle", type=Path, help="check links in a packaged C release ZIP")
    mode.add_argument("--release-version", help="check release documents and UniFFI guide without writing references")
    args = parser.parse_args()
    if args.c_bundle:
        try:
            _check_c_bundle(args.c_bundle)
        except (BadZipFile, KeyError, OSError, ValueError) as error:
            parser.exit(1, f"{args.c_bundle}: {error}\n")
        return 0

    if args.release_version:
        problems = release_problems(REPO, args.release_version)
        if problems:
            parser.exit(1, "\n".join(problems) + "\n")

    catalogs = [(REPO / "crates/marmot-uniffi", "rust", uniffi_catalog())]
    if args.with_c:
        crate = REPO / "crates/marmot-c"
        catalogs.append((crate, "c", c_exports_in((crate / "include/marmot.h").read_text())))
    for crate, language, exports in catalogs:
        guide = crate / "API-GUIDE.md"
        try:
            reference = render(guide.read_text(), language, exports)
        except ValueError as error:
            parser.exit(1, f"{guide.relative_to(REPO)}:\n{error}\n")
        if not args.release_version:
            if args.with_c:
                peer = "marmot-uniffi" if language == "c" else "marmot-c"
                reference = reference.replace(f"../{peer}/API-GUIDE.md", f"../{peer}/API-REFERENCE.md")
            output = crate / "API-REFERENCE.md"
            output.write_text("<!-- Generated from API-GUIDE.md and declarations. Do not edit. -->\n\n" + reference)
            print(f"{output.relative_to(REPO)}: {len(exports)} callables")
    if args.release_version:
        print(f"release documentation preflight passed for {args.release_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
