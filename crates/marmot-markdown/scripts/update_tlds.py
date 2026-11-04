#!/usr/bin/env python3
"""Validate and install an explicitly downloaded IANA root snapshot, offline."""
import argparse
import hashlib
import re
from pathlib import Path


def validated(data):
    text = data.decode("ascii")
    lines = text.splitlines()
    if not lines or not re.fullmatch(r"# Version \d+, Last Updated .+ UTC", lines[0]):
        raise ValueError("missing IANA version/date header")
    roots = lines[1:]
    if not roots or roots != sorted(set(roots)):
        raise ValueError("root labels must be nonempty, sorted and unique")
    if not all(re.fullmatch(r"[A-Z](?:[A-Z0-9-]{0,61}[A-Z0-9])?", root) for root in roots):
        raise ValueError("invalid root label")
    if not {"COM", "ORG", "NET", "CHAT", "NETWORK"}.issubset(roots):
        raise ValueError("incomplete root snapshot")
    if not text.endswith("\n"):
        raise ValueError("missing final newline")
    return set(roots)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    data = args.candidate.read_bytes()
    proposed = validated(data)
    target = Path(__file__).resolve().parents[1] / "src" / "iana-tlds.txt"
    previous = validated(target.read_bytes())
    print("SHA256", hashlib.sha256(data).hexdigest())
    print("Added:", ", ".join(sorted(proposed - previous)) or "none")
    print("Removed:", ", ".join(sorted(previous - proposed)) or "none")
    if target.read_bytes() != data:
        target.write_bytes(data)


if __name__ == "__main__":
    main()
