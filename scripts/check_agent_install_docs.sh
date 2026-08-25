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

python3 - "$workspace_version" <<'PY'
from pathlib import Path
import sys

version = sys.argv[1]
quickstart = Path("integrations/README.md").read_text(encoding="utf-8")
release_guide = Path("release.md").read_text(encoding="utf-8")
base_url = (
    "https://github.com/marmot-protocol/mdk/releases/download/"
    f"wn-agent-v{version}"
)
if quickstart.count(f'base_url="{base_url}"') != 1:
    print(
        "error: integrations/README.md must define exactly one immutable current-release base_url "
        f"({base_url})",
        file=sys.stderr,
    )
    raise SystemExit(1)
if release_guide.count(f'base_url="{base_url}"') != 1:
    print(
        "error: release.md must define exactly one immutable current-release base_url "
        f"({base_url})",
        file=sys.stderr,
    )
    raise SystemExit(1)
for connector in ("hermes", "openclaw", "codex", "opencode", "pi"):
    installer = f"install-{connector}-marmot.sh"
    call = f'install_verified "$base_url/{installer}"'
    checksum = f'"$base_url/{installer}.sha256"'
    if quickstart.count(call) < 1 or quickstart.count(checksum) < 1:
        print(
            "error: integrations/README.md must verify the current "
            f"{connector} installer against its companion checksum before execution",
            file=sys.stderr,
        )
        raise SystemExit(1)
PY

if rg -n 'releases/download/wn-agent-latest/install-' "${active_paths[@]}"; then
    echo "error: active agent install guidance must use an immutable versioned release" >&2
    exit 1
fi

stale_versioned_urls="$(
    rg -n -o 'wn-agent-v[0-9]+\.[0-9]+\.[0-9]+/install-(hermes|openclaw|codex|opencode|pi)-marmot\.sh' \
        "${active_paths[@]}" |
        grep -F -v "wn-agent-v${workspace_version}/" || true
)"
if [ -n "$stale_versioned_urls" ]; then
    printf '%s\n' "$stale_versioned_urls" >&2
    echo "error: agent install guidance does not match workspace version $workspace_version" >&2
    exit 1
fi

if rg -n 'releases/download/\$latest_tag/install-' .github/workflows/wn-agent-binaries.yml; then
    echo "error: generated release notes must link to the immutable release tag" >&2
    exit 1
fi

echo "agent install documentation matches wn-agent-v$workspace_version"
