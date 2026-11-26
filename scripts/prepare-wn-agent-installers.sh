#!/usr/bin/env bash
set -euo pipefail

# Generate all eight version-pinned WN Agent installers and sibling .sha256 files.
# Shared by both tag-pushed and promoted-Stable jobs in wn-agent-binaries.yml.

tag="${1:?usage: prepare-wn-agent-installers.sh <tag> <version> <source-root> <out-dir>}"
version="${2:?usage: prepare-wn-agent-installers.sh <tag> <version> <source-root> <out-dir>}"
source_root="${3:?usage: prepare-wn-agent-installers.sh <tag> <version> <source-root> <out-dir>}"
out_dir="${4:?usage: prepare-wn-agent-installers.sh <tag> <version> <source-root> <out-dir>}"

mkdir -p "$out_dir"

sed \
  -e "s/^MARMOT_RELEASE_TAG_DEFAULT=.*/MARMOT_RELEASE_TAG_DEFAULT=\"${tag}\"/" \
  -e "s/^WN_AGENT_VERSION_DEFAULT=.*/WN_AGENT_VERSION_DEFAULT=\"${version}\"/" \
  "$source_root/scripts/install-hermes-marmot.sh" > "$out_dir/install-hermes-marmot.sh"
chmod 0755 "$out_dir/install-hermes-marmot.sh"

sed \
  -e "s/^MARMOT_RELEASE_TAG_DEFAULT=.*/MARMOT_RELEASE_TAG_DEFAULT=\"${tag}\"/" \
  -e "s/^WN_AGENT_VERSION_DEFAULT=.*/WN_AGENT_VERSION_DEFAULT=\"${version}\"/" \
  "$source_root/scripts/install-openclaw-marmot.sh" > "$out_dir/install-openclaw-marmot.sh"
chmod 0755 "$out_dir/install-openclaw-marmot.sh"

for harness in claude codex opencode pi goose; do
  awk -v harness="$harness" \
    'NR == 1 { print; print "export MARMOT_TERMINAL_HARNESS=" harness; next } { print }' \
    "$source_root/scripts/install-terminal-harness-marmot.sh" | \
    sed \
      -e "s/^MARMOT_RELEASE_TAG_DEFAULT=.*/MARMOT_RELEASE_TAG_DEFAULT=\"${tag}\"/" \
      -e "s/^WN_AGENT_VERSION_DEFAULT=.*/WN_AGENT_VERSION_DEFAULT=\"${version}\"/" \
      > "$out_dir/install-$harness-marmot.sh"
  chmod 0755 "$out_dir/install-$harness-marmot.sh"
done

# Connector-only mode of the same installer, for custom agent-control clients.
awk 'NR == 1 { print; print "export MARMOT_TERMINAL_HARNESS=none"; next } { print }' \
  "$source_root/scripts/install-terminal-harness-marmot.sh" | \
  sed \
    -e "s/^MARMOT_RELEASE_TAG_DEFAULT=.*/MARMOT_RELEASE_TAG_DEFAULT=\"${tag}\"/" \
    -e "s/^WN_AGENT_VERSION_DEFAULT=.*/WN_AGENT_VERSION_DEFAULT=\"${version}\"/" \
    > "$out_dir/install-wn-agent.sh"
chmod 0755 "$out_dir/install-wn-agent.sh"

for installer in "$out_dir"/install-*.sh; do
  shasum -a 256 "$installer" | \
    awk -v name="$(basename "$installer")" '{print $1 "  " name}' \
    > "$installer.sha256"
done
