#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
[ -n "$workspace_version" ] || {
    echo "error: could not read the workspace version" >&2
    exit 1
}

active_paths=(
    README.md
    integrations
    crates/agent-connector/README.md
    release.md
    scripts/install-hermes-marmot.sh
    scripts/install-openclaw-marmot.sh
    scripts/install-terminal-harness-marmot.sh
    .github/workflows/wn-agent-binaries.yml
)

python3 - "$workspace_version" "${active_paths[@]}" <<'PY'
from pathlib import Path
import re
import subprocess
import sys

version = sys.argv[1]
quickstart = Path("integrations/README.md").read_text(encoding="utf-8")
release_guide = Path("release.md").read_text(encoding="utf-8")
base_url = (
    "https://github.com/marmot-protocol/mdk/releases/download/"
    f"wn-agent-v{version}"
)
# Quickstarts and the release record default to the documented release.
# Latest selection is optional and centralized; preserve checksum pairing.
sys.path.insert(0, str(Path("scripts").resolve()))
from check_install_example_sha256 import optional_latest_release_errors
errors = optional_latest_release_errors(quickstart)
if errors:
    print("error: integrations/README.md: " + "; ".join(errors), file=sys.stderr)
    raise SystemExit(1)
for label, text in (("integrations/README.md", quickstart), ("release.md", release_guide)):
    if text.count(f'base_url="{base_url}"') != 1:
        print(
            f"error: {label} must define exactly one immutable current-release base_url "
            f"({base_url})",
            file=sys.stderr,
        )
        raise SystemExit(1)
quickstart_expected_calls = {"hermes": 2, "openclaw": 1, "claude": 1, "codex": 2, "opencode": 1, "pi": 1, "goose": 1}
for connector, quickstart_expected in quickstart_expected_calls.items():
    installer = f"install-{connector}-marmot.sh"
    call = f'install_verified "$base_url/{installer}"'
    checksum = f'"$base_url/{installer}.sha256"'
    for label, text, expected in (
        ("integrations/README.md", quickstart, quickstart_expected),
        ("release.md", release_guide, 1),
    ):
        if text.count(call) != expected or text.count(checksum) != expected:
            print(
                f"error: {label} must contain exactly {expected} current {connector} installer call(s) "
                "paired with companion checksums",
                file=sys.stderr,
            )
            raise SystemExit(1)
# Inspect tracked source paths without requiring ripgrep on hosted runners.
# A failed file listing/read must fail the gate rather than look like no matches.
def tracked(paths):
    output = subprocess.check_output(["git", "ls-files", "-z", "--", *paths])
    return [Path(name.decode()) for name in output.split(b"\0") if name]

for path in tracked(sys.argv[2:]):
    text = path.read_text(encoding="utf-8", errors="replace")
    if "releases/download/wn-agent-latest/install-" in text:
        raise SystemExit(f"error: {path}: active install guidance uses a mutable release alias")
    for match in re.finditer(
        r"wn-agent-v[0-9]+\.[0-9]+\.[0-9]+/install-(?:hermes|openclaw|claude|codex|opencode|pi|goose)-marmot\.sh", text
    ):
        if not match.group().startswith(f"wn-agent-v{version}/"):
            raise SystemExit(f"error: {path}: agent install guidance does not match workspace version {version}")
for path in tracked([".github/workflows"]):
    if "wn-agent-latest" in path.read_text(encoding="utf-8", errors="replace"):
        raise SystemExit(f"error: {path}: release workflows advertise a mutable WN Agent alias")
PY

echo "agent install documentation: shared verified helper, release pins and optional latest selection are valid"
