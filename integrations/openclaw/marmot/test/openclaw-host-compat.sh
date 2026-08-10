#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
beta_version="2026.7.2-beta.7"
update_lock=false
case "${1:-}" in
  "") ;;
  --update-lock) update_lock=true ;;
  *)
    echo "usage: $0 [--update-lock]" >&2
    exit 2
    ;;
esac
compat_root="$(mktemp -d "${TMPDIR:-/tmp}/openclaw-host-compat.XXXXXX")"
trap 'rm -rf "$compat_root"' EXIT

# Fail with a direct diagnostic if the pinned beta has disappeared instead of
# letting dependency installation fail later with a less useful resolver error.
published_version="$(npm view "openclaw@$beta_version" version 2>/dev/null || true)"
if [ "$published_version" != "$beta_version" ]; then
  echo "error: OpenClaw beta $beta_version is not available from npm" >&2
  exit 1
fi

cp "$plugin_dir/package.json" "$compat_root/"
cp "$plugin_dir/test/pnpm-lock.openclaw-beta.yaml" "$compat_root/pnpm-lock.yaml"
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
if [ "$update_lock" = true ]; then
  pnpm install --ignore-scripts --lockfile-only
  cp pnpm-lock.yaml "$plugin_dir/test/pnpm-lock.openclaw-beta.yaml"
  echo "updated $plugin_dir/test/pnpm-lock.openclaw-beta.yaml"
  exit 0
fi
# This dedicated lock fixes the complete beta dependency graph while the
# compatibility lane exercises the deliberately different host SDK contract.
pnpm install --ignore-scripts --frozen-lockfile
pnpm build
OPENCLAW_HOST_COMPAT_EXPECT_FLUSH_PAIR=1 pnpm vitest run \
  test/openclaw-host-contract.test.ts \
  test/dispatch.test.ts \
  test/inbound-runtime.test.ts \
  test/bounded-keyed-async-queue.test.ts \
  test/outbound.test.ts \
  test/plugin-sdk-surface.test.ts
