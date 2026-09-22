#!/usr/bin/env python3
"""Serialize known MarmotKit Rust release-profile variables as typed JSON."""

from __future__ import annotations

import json
import os
import sys
from typing import Mapping


FIELD_SPECS = (
    ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "opt_level", "string"),
    ("CARGO_PROFILE_RELEASE_DEBUG", "debug", "string"),
    ("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "debug_assertions", "bool"),
    ("CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "overflow_checks", "bool"),
    ("CARGO_PROFILE_RELEASE_LTO", "lto", "lto"),
    ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "codegen_units", "int"),
    ("CARGO_PROFILE_RELEASE_PANIC", "panic", "string"),
    ("CARGO_PROFILE_RELEASE_STRIP", "strip", "string"),
)

KNOWN_ENV_VARS = {name for name, _, _ in FIELD_SPECS}


class ProfileError(ValueError):
    """A known profile variable is missing or has an untyped value."""


def _parse_bool(name: str, raw: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ProfileError(f"{name} must be true or false, got {raw!r}")


def _parse_int(name: str, raw: str) -> int:
    if not raw.isdigit():
        raise ProfileError(f"{name} must be a non-negative integer, got {raw!r}")
    return int(raw)


def _parse_lto(name: str, raw: str):
    if raw in {"true", "false"}:
        return raw == "true"
    if raw in {"thin", "fat", "off"}:
        return raw
    raise ProfileError(
        f"{name} must be true, false, thin, fat, or off, got {raw!r}"
    )


def profile_from_env(env: Mapping[str, str] | None = None) -> dict:
    """Return the typed rust_release_profile object from known variables only."""
    source = os.environ if env is None else env
    profile = {}
    for name, field, kind in FIELD_SPECS:
        if name not in source:
            raise ProfileError(f"missing {name}")
        raw = source[name]
        if raw == "":
            raise ProfileError(f"{name} must not be empty")
        if kind == "string":
            profile[field] = raw
        elif kind == "bool":
            profile[field] = _parse_bool(name, raw)
        elif kind == "int":
            profile[field] = _parse_int(name, raw)
        elif kind == "lto":
            profile[field] = _parse_lto(name, raw)
        else:
            raise ProfileError(f"unknown field type {kind}")
    return profile


def profile_json(env: Mapping[str, str] | None = None) -> str:
    return json.dumps(profile_from_env(env), separators=(",", ":"), ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        sys.stderr.write("usage: release-profile-json.py\n")
        return 2
    try:
        sys.stdout.write(profile_json())
        sys.stdout.write("\n")
    except ProfileError as error:
        sys.stderr.write(f"error: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
