#!/usr/bin/env bash
# Upstream dev-2026-10 resolves to 84bc3fc2100b0f7880a3af37f71bccdcda41c6f9:
# https://api.github.com/repos/odin-lang/Odin/git/ref/tags/dev-2026-10
# SHA-256 pins are the upstream release asset digests, recorded from:
# https://api.github.com/repos/odin-lang/Odin/releases/tags/dev-2026-10
set -euo pipefail

if [[ $# != 1 || "$1" != /* ]]; then
  echo "usage: bash scripts/install-odin.sh /absolute/install/directory" >&2
  exit 1
fi
destination="$1"
version=dev-2026-10
expected_commit=84bc3fc
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    platform=linux-amd64
    sha256=c3c8b095621fd0c75f7f73e3a0829f1b4d45324225f20ba11ed8dc4da310a8ab
    ;;
  Linux:aarch64|Linux:arm64)
    platform=linux-arm64
    sha256=99c43e9670a285901d6cfee5f56197b74c7d6f7c537b35ecba0c1b44ac2e4df8
    ;;
  Darwin:arm64)
    platform=macos-arm64
    sha256=b276c6ac87c3eea17446a6ca9080089b6e9f492057fb773591775ee49d92a1cf
    ;;
  MINGW*:x86_64|MSYS*:x86_64)
    platform=windows-amd64
    sha256=b6b2e426a8b6f147b74ec7e18bef8df27cf40fe16193159df7ca09a0cc0c2011
    ;;
  *)
    echo "error: no pinned Odin binary for host $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

extension=tar.gz
executable=odin
if [[ "$platform" == windows-* ]]; then
  extension=zip
  executable=odin.exe
fi
asset="odin-$platform-$version.$extension"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/$asset"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "https://github.com/odin-lang/Odin/releases/download/$version/$asset" \
  --output "$archive"
# Verify the archive before extracting or executing any upstream content.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$work" && printf '%s  %s\n' "$sha256" "$asset" | sha256sum --check --status)
else
  (cd "$work" && printf '%s  %s\n' "$sha256" "$asset" | shasum --algorithm 256 --check --status)
fi
mkdir "$work/unpack"
if [[ "$extension" == zip ]]; then
  ODIN_ARCHIVE="$(cygpath -w "$archive")" ODIN_UNPACK="$(cygpath -w "$work/unpack")" \
    powershell.exe -NoProfile -NonInteractive -Command \
      'Expand-Archive -LiteralPath $env:ODIN_ARCHIVE -DestinationPath $env:ODIN_UNPACK'
else
  tar -xzf "$archive" -C "$work/unpack"
fi

# Unix archives have a versioned root directory; Windows archives may not.
root=""
for candidate in "$work/unpack" "$work/unpack"/*; do
  if [[ -f "$candidate/$executable" ]]; then
    root="$candidate"
    break
  fi
done
if [[ -z "$root" ]]; then
  echo "error: pinned Odin archive does not contain $executable" >&2
  exit 1
fi
mkdir -p "$destination"
cp -R "$root/." "$destination/"
actual_version="$("$destination/$executable" version)"
if [[ "$actual_version" != *"version $version"* || "$actual_version" != *":$expected_commit"* ]]; then
  echo "error: expected Odin $version at $expected_commit, got $actual_version" >&2
  exit 1
fi
printf '%s\n' "$actual_version"
