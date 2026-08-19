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

for connector in hermes openclaw codex opencode pi; do
    expected="releases/download/wn-agent-v${workspace_version}/install-${connector}-marmot.sh"
    if ! rg -F -q "$expected" integrations/README.md; then
        echo "error: integrations/README.md is missing the current $connector installer URL ($expected)" >&2
        exit 1
    fi
done

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
