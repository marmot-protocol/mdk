#!/usr/bin/env python3
"""Check complete binding-reference names/signatures against current source exports.

Run from any directory: python3 scripts/check_binding_docs.py
This checks inventory, not semantic prose, generated-language ABI, or artifact adoption.
It uses the same simple export-block reader as the C parity gate and additionally
covers exported free functions and foreign callback traits. Unsupported export shapes
fail closed so a future macro/attribute change cannot silently reduce the inventory.
"""
from __future__ import annotations

import re
from pathlib import Path

from check_c_binding_parity import REPO, UNIFFI_SRC, _braced_block, uniffi_exports


def normalized(value: str) -> str:
    return " ".join(value.split())


def uniffi_signatures() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(UNIFFI_SRC.rglob("*.rs")):
        text = path.read_text()
        for export in re.finditer(r"#\[uniffi::export[^\]]*\]\s*\n", text):
            tail = text[export.end():]
            owner_match = re.match(r"(?:impl|pub trait)\s+(\w+)[^{]*\{", tail)
            if owner_match:
                owner = owner_match[1]
                body = _braced_block(tail, tail.index("{"))
                methods = re.finditer(r"\n    (?:pub )?(?:async )?fn (\w+)\s*\(", body)
            elif re.match(r"pub (?:async )?fn ", tail):
                owner, body = "free", tail
                methods = [re.match(r"pub (?:async )?fn (\w+)\s*\(", body)]
            else:
                raise ValueError(f"unsupported UniFFI export shape in {path}")
            for method in methods:
                key = f"{owner}::{method[1]}"
                signature = re.split(r"\{|;", body[method.start():], maxsplit=1)[0]
                if key in result:
                    raise ValueError(f"duplicate export {key}")
                result[key] = normalized(signature)
    # Cross-check all object methods against the existing C-parity inventory.
    expected = {key if "::" in key else f"Marmot::{key}" for key in uniffi_exports()}
    if not expected <= result.keys():
        raise ValueError(f"missed parity exports: {sorted(expected - result.keys())}")
    return result


def c_signatures() -> dict[str, str]:
    header = (REPO / "crates/marmot-c/include/marmot.h").read_text()
    header = re.sub(r"/\*.*?\*/", "", header, flags=re.DOTALL)
    pattern = r"(?m)^([A-Za-z_][\w\s*]*?\b(marmot_\w+)\s*\([^;]*?\));"
    result = {match[2]: normalized(match[1]) + ";" for match in re.finditer(pattern, header)}
    names = set(re.findall(r"\b(marmot_\w+)\s*\(", header))
    if names != result.keys():
        raise ValueError(f"unparsed C declarations: {sorted(names - result.keys())}")
    return result


def check(path: Path, language: str, expected: dict[str, str]) -> list[str]:
    text = path.read_text()
    entries = re.findall(r"^### `([^`]+)`\n(.*?)(?=^### |\Z)", text, re.MULTILINE | re.DOTALL)
    actual: dict[str, str] = {}
    errors: list[str] = []
    for key, body in entries:
        code = re.search(rf"```{language}\n(.*?)\n```", body, re.DOTALL)
        if key in actual:
            errors.append(f"duplicate documented method: {key}")
        actual[key] = normalized(code[1]) if code else ""
    errors.extend(f"missing method: {key}" for key in sorted(expected.keys() - actual.keys()))
    errors.extend(f"removed/unknown method: {key}" for key in sorted(actual.keys() - expected.keys()))
    errors.extend(f"changed signature: {key}" for key in sorted(expected.keys() & actual.keys())
                  if expected[key] != actual[key])
    for error in errors:
        print(f"{path.relative_to(REPO)}: {error}")
    if not errors:
        print(f"{path.relative_to(REPO)}: {len(expected)} callables documented with matching signatures")
    return errors


def main() -> int:
    errors = check(REPO / "crates/marmot-uniffi/API-REFERENCE.md", "rust", uniffi_signatures())
    errors += check(REPO / "crates/marmot-c/API-REFERENCE.md", "c", c_signatures())
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
