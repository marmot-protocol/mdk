#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
beta_version="${1:-2026.7.2-beta.7}"
compat_root="$(mktemp -d "${TMPDIR:-/tmp}/openclaw-host-compat.XXXXXX")"
trap 'rm -rf "$compat_root"' EXIT

cp "$plugin_dir/package.json" "$compat_root/"
cp "$plugin_dir/pnpm-workspace.yaml" "$compat_root/"
cp "$plugin_dir/tsconfig.json" "$compat_root/"
cp "$plugin_dir/tsconfig.build.json" "$compat_root/"
cp "$plugin_dir/vitest.config.ts" "$compat_root/"
cp "$plugin_dir/index.ts" "$compat_root/"
cp "$plugin_dir/setup-entry.ts" "$compat_root/"
cp -R "$plugin_dir/src" "$compat_root/"
cp -R "$plugin_dir/test" "$compat_root/"

cd "$compat_root"
npm pkg set "devDependencies.openclaw=$beta_version" >/dev/null
pnpm install --ignore-scripts --lockfile=false
pnpm build
pnpm vitest run \
  test/openclaw-host-contract.test.ts \
  test/dispatch.test.ts \
  test/inbound-runtime.test.ts \
  test/bounded-keyed-async-queue.test.ts \
  test/outbound.test.ts \
  test/plugin-sdk-surface.test.ts
