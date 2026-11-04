#!/usr/bin/env python3
"""Validate and install an explicitly downloaded IANA root snapshot, offline."""
import argparse
import hashlib
import os
import tempfile
import re
from pathlib import Path


def validated(data):
    text = data.decode("ascii")
    if any(ord(c) < 32 and c != "\n" for c in text):
        raise ValueError("root snapshot permits LF line endings only")
    lines = text.removesuffix("\n").split("\n")
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
    print(f"Roots: {len(previous)} -> {len(proposed)}")
    print("Added:", ", ".join(sorted(proposed - previous)) or "none")
    print("Removed:", ", ".join(sorted(previous - proposed)) or "none")
    if target.read_bytes() != data:
        fd, temporary = tempfile.mkstemp(prefix=".iana-tlds-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), target.stat().st_mode & 0o777)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if __name__ == "__main__":
    main()
