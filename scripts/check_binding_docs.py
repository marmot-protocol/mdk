#!/usr/bin/env python3
"""Check or refresh binding-reference metadata while preserving authored guidance.

Use --write to refresh signatures/source links and scaffold newly exported methods.
New scaffolds deliberately fail validation until an author supplies integration prose.
Removed and duplicate entries require editorial cleanup; they are never silently deleted.
This source inventory does not validate semantic prose, DTOs, or generated-language ABI.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import tomllib

from check_c_binding_parity import REPO, UNIFFI_SRC, _braced_block, uniffi_exports

ENTRY = re.compile(r"^### `([^`]+)`\n(.*?)(?=^### |^</details>|\Z)", re.MULTILINE | re.DOTALL)
NEEDS_PROSE = "AUTHOR REQUIRED: explain purpose, API choice and integration constraints."


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


def source_pattern(language: str) -> str:
    """Match the one mechanical source link, not other authored documentation links."""
    label = "Source" if language == "rust" else "Header contract"
    return rf"\[{label}\]\(([^)]+)\)"


def scaffold(key: str, export: Export, language: str) -> str:
    """Produce a new entry with a blocking marker for missing human-authored prose."""
    label = "Source" if language == "rust" else "Header contract"
    return (f"### `{key}`\n\n```{language}\n{export.signature}\n```\n\n"
            f"{NEEDS_PROSE}\n\n[{label}]({export.source})\n\n")


def refresh(text: str, language: str, expected: dict[str, Export]) -> str:
    """Refresh metadata only; preserve prose and retain removed entries for review."""
    seen: set[str] = set()
    code_pattern = rf"```{language}\n.*?\n```"
    link_pattern = source_pattern(language)
    label = "Source" if language == "rust" else "Header contract"

    def replace(match: re.Match) -> str:
        key, body = match[1], match[2]
        if key in seen:
            raise ValueError(f"duplicate documented method: {key}; resolve before --write")
        seen.add(key)
        if key not in expected:
            return match[0]
        export = expected[key]
        code = f"```{language}\n{export.signature}\n```"
        if re.search(code_pattern, body, re.DOTALL):
            body = re.sub(code_pattern, lambda _: code, body, count=1, flags=re.DOTALL)
        else:
            body = "\n" + code + "\n" + body
        link = f"[{label}]({export.source})"
        if re.search(link_pattern, body):
            body = re.sub(link_pattern, lambda _: link, body)
        else:
            body = body.rstrip() + "\n\n" + link + "\n\n"
        return f"### `{key}`\n{body}"

    refreshed = ENTRY.sub(replace, text)
    missing = sorted(expected.keys() - seen)
    if missing:
        refreshed = refreshed.rstrip() + "\n\n<details>\n<summary>New exports — complete and organize before merging</summary>\n\n"
        refreshed += "".join(scaffold(key, expected[key], language) for key in missing)
        refreshed += "</details>\n"
    return refreshed


def check(text: str, language: str, expected: dict[str, Export]) -> list[str]:
    """Report missing/stale/duplicate entries, signature/link drift and empty scaffolds."""
    actual: dict[str, str] = {}
    errors: list[str] = []
    for match in ENTRY.finditer(text):
        key, body = match[1], match[2]
        if key in actual:
            errors.append(f"duplicate documented method: {key}")
        actual[key] = body
    errors.extend(f"missing method: {key}; run --write to scaffold" for key in sorted(expected.keys() - actual.keys()))
    errors.extend(f"removed/unknown method: {key}; review and remove explicitly" for key in sorted(actual.keys() - expected.keys()))
    for key in sorted(expected.keys() & actual.keys()):
        body, export = actual[key], expected[key]
        codes = re.findall(rf"```{language}\n(.*?)\n```", body, re.DOTALL)
        actual_signature = normalized(codes[0]) if len(codes) == 1 else "<missing or multiple signature blocks>"
        if actual_signature != export.signature:
            errors.append(f"changed signature: {key}\n  actual:   {actual_signature}\n  expected: {export.signature}\n  run --write to refresh")
        links = re.findall(source_pattern(language), body)
        if links != [export.source]:
            errors.append(f"changed source link: {key}\n  actual:   {links}\n  expected: {export.source}\n  run --write to refresh")
        if NEEDS_PROSE in body:
            errors.append(f"missing authored guidance: {key}")
    return errors


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


def main() -> int:
    """Validate both references, optionally refreshing their mechanical metadata first."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="refresh signatures/links and scaffold new exports; preserve prose")
    parser.add_argument("--release-version", help="also verify this workspace version has companion release documents")
    args = parser.parse_args()
    catalogs = [(REPO / "crates/marmot-uniffi/API-REFERENCE.md", "rust", uniffi_catalog()),
                (REPO / "crates/marmot-c/API-REFERENCE.md", "c",
                 c_exports_in((REPO / "crates/marmot-c/include/marmot.h").read_text()))]
    errors: list[str] = []
    for path, language, expected in catalogs:
        text = path.read_text()
        if args.write:
            updated = refresh(text, language, expected)
            if updated != text:
                path.write_text(updated)
            text = updated
        problems = check(text, language, expected)
        for problem in problems:
            print(f"{path.relative_to(REPO)}: {problem}")
        if not problems:
            print(f"{path.relative_to(REPO)}: {len(expected)} callables; signatures and source links match")
        errors += problems
    if args.release_version:
        problems = release_problems(REPO, args.release_version)
        for problem in problems:
            print(problem)
        if not problems:
            print(f"release documentation preflight passed for {args.release_version}")
        errors += problems
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
