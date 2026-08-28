#!/usr/bin/env python3
"""Gate `marmot-c` against the `marmot-uniffi` command surface.

`crates/marmot-c` promises raw-FFI hosts the same runtime surface UniFFI
gives Swift/Kotlin. Nothing enforced that, so a command added upstream
could sit unexported indefinitely and nobody would notice.

This compares every method exported from a `#[uniffi::export] impl Marmot`
block against the methods `marmot-c` actually calls, and fails on any
difference the allowlist below does not explain.

Usage:
    scripts/check_c_binding_parity.py            # gate (exit 1 on drift)
    scripts/check_c_binding_parity.py --list     # print the current gap
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UNIFFI_SRC = REPO / "crates" / "marmot-uniffi" / "src"
C_SRC = REPO / "crates" / "marmot-c" / "src"

# Commands deliberately absent from the C ABI, each with the reason it is
# not drift. Removing an entry here is how you turn it back into a gap.
DELIBERATELY_UNEXPORTED = {
    "register_external_signer": (
        "Takes a host-implemented ExternalAccountSignerFfi trait. A C mapping "
        "needs a callback vtable (function pointers + user_data) invoked from "
        "runtime worker threads, with owned-string returns and error "
        "signalling. Deserves its own design + tests; see AGENTS.md."
    ),
    "login_external_signer": (
        "Same host-implemented signer trait as register_external_signer."
    ),
}


def uniffi_exports() -> dict[str, str]:
    """Method name -> defining file, for every `#[uniffi::export] impl Marmot`."""
    exports: dict[str, str] = {}
    for path in sorted(UNIFFI_SRC.rglob("*.rs")):
        src = path.read_text()
        for match in re.finditer(r"#\[uniffi::export[^\]]*\]\s*\nimpl\s+(\w+)\s*\{", src):
            if match.group(1) != "Marmot":
                continue
            body = _braced_block(src, src.index("{", match.end() - 1))
            for fn in re.finditer(r"\n    pub (?:async )?fn (\w+)\s*\(", body):
                exports.setdefault(fn.group(1), path.name)
    return exports


def _braced_block(src: str, start: int) -> str:
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i]
    raise ValueError("unbalanced braces")


def c_coverage() -> set[str]:
    """Runtime methods `marmot-c` calls, however the call is line-wrapped."""
    # Whitespace is stripped wholesale so rustfmt's multi-line call chains
    # (`client\n    .marmot\n    .method(...)`) collapse to one token.
    src = re.sub(r"\s+", "", "".join(p.read_text() for p in C_SRC.rglob("*.rs")))
    return (
        set(re.findall(r"\.marmot\.(\w+)\(", src))
        # c_cmd! `fn marmot_x(..) -> rec(T) = method;` — anchor on the return
        # form so a plain assignment cannot pass as coverage.
        | set(re.findall(r"->[\w()]+=(\w+);", src))
        # Called, or handed to `open_client` as a bare function item
        # (`Marmot::new,`).
        | set(re.findall(r"Marmot::(\w+)[(,]", src))
    )


def main() -> int:
    exports = uniffi_exports()
    covered = c_coverage()
    missing = sorted(n for n in exports if n not in covered)

    stale = sorted(n for n in DELIBERATELY_UNEXPORTED if n not in exports)
    gaps = [n for n in missing if n not in DELIBERATELY_UNEXPORTED]

    if "--list" in sys.argv:
        print(f"exported={len(exports)} covered={len(exports) - len(missing)} gaps={len(gaps)}")
        by_file: dict[str, list[str]] = {}
        for name in gaps:
            by_file.setdefault(exports[name], []).append(name)
        for file in sorted(by_file):
            print(f"\n{file}:")
            for name in by_file[file]:
                print(f"    {name}")
        return 0

    ok = True
    if gaps:
        ok = False
        print(
            f"error: {len(gaps)} marmot-uniffi command(s) have no marmot-c wrapper.\n"
            "Export them, or add an entry to DELIBERATELY_UNEXPORTED explaining why not:",
            file=sys.stderr,
        )
        for name in gaps:
            print(f"    {name}  ({exports[name]})", file=sys.stderr)

    if stale:
        ok = False
        print(
            "\nerror: DELIBERATELY_UNEXPORTED names commands that no longer exist "
            "upstream; drop them:",
            file=sys.stderr,
        )
        for name in stale:
            print(f"    {name}", file=sys.stderr)

    if ok:
        print(f"c-binding parity: {len(exports)} commands, all exported or explained")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
