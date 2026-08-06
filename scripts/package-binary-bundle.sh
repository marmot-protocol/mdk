#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: package-binary-bundle.sh <binary> <target> <rust-target>}"
target="${2:?usage: package-binary-bundle.sh <binary> <target> <rust-target>}"
rust_target="${3:?usage: package-binary-bundle.sh <binary> <target> <rust-target>}"

case "$binary" in
    wn-agent | wn-opencode | wn-pi | wn-prime-agent) ;;
    *) echo "error: unsupported release binary: $binary" >&2; exit 64 ;;
esac
if [[ ! "$target" =~ ^[A-Za-z0-9._-]+$ ]] || [[ ! "$rust_target" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "error: release target names must contain only letters, digits, dots, underscores, or dashes" >&2
    exit 64
fi

sha_short="${GITHUB_SHA::12}"
workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
release_tag=""
artifact_version="$sha_short"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
    release_tag="${GITHUB_REF_NAME:?GITHUB_REF_NAME is required for tag builds}"
    if [[ ! "$release_tag" =~ ^wn-agent-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
        echo "error: wn-agent releases must use a version tag like wn-agent-v0.1.0" >&2
        exit 1
    fi
    artifact_version="${release_tag#wn-agent-v}"
    if [ "$artifact_version" != "$workspace_version" ]; then
        echo "error: wn-agent release version $artifact_version does not match workspace version $workspace_version" >&2
        exit 1
    fi
fi

lock_sha="$(shasum -a 256 Cargo.lock | awk '{print $1}')"
stage_parent="${RUNNER_TEMP:?RUNNER_TEMP is required}/$binary-stage"
bundle_dir="$stage_parent/$binary-$target"
asset="$RUNNER_TEMP/$binary-$target-$artifact_version.tar.gz"
dist_root="${BUNDLE_DIST_ROOT:-dist}"

rm -rf "$stage_parent"
rm -f "$asset" "$asset.sha256"
mkdir -p "$bundle_dir"
install -m 0755 "target/$rust_target/release/$binary" "$bundle_dir/$binary"

cat > "$bundle_dir/manifest.json" <<EOF
{
  "name": "$binary",
  "target": "$target",
  "rust_target": "$rust_target",
  "release_tag": "$release_tag",
  "artifact_version": "$artifact_version",
  "source_sha": "$GITHUB_SHA",
  "workspace_version": "$workspace_version",
  "cargo_lock_sha256": "$lock_sha",
  "rustc": "$(rustc --version)",
  "cargo": "$(cargo --version)",
  "contents": [
    "$binary",
    "manifest.json"
  ]
}
EOF

(
    cd "$stage_parent"
    tar -czf "$asset" "$binary-$target"
)
shasum -a 256 "$asset" | awk -v name="$(basename "$asset")" '{print $1 "  " name}' > "$asset.sha256"
mkdir -p "$dist_root/$binary-$target"
cp "$asset" "$asset.sha256" "$dist_root/$binary-$target/"
