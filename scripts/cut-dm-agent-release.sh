#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: cut-dm-agent-release.sh [--dry-run] [--no-push] <version>

Create and push the annotated dm-agent release tag for the current workspace
version. The tag is cut from origin/master so the GitHub release workflow can
publish immutable dm-agent-v<version> assets.

Options:
  --dry-run   Print the release action without creating or pushing a tag
  --no-push   Create the local tag but do not push it
  -h, --help  Show this help

Example:
  ./scripts/cut-dm-agent-release.sh 0.1.0
USAGE
}

dry_run=0
push=1
version=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            dry_run=1
            shift
            ;;
        --no-push)
            push=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -n "$version" ]; then
                echo "error: multiple versions provided" >&2
                usage >&2
                exit 2
            fi
            version="$1"
            shift
            ;;
    esac
done

if [ -z "$version" ]; then
    echo "error: version is required" >&2
    usage >&2
    exit 2
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "error: version must be semver-like, for example 0.1.0 or 0.1.0-alpha.1" >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
if [ "$workspace_version" != "$version" ]; then
    echo "error: Cargo.toml workspace version is $workspace_version, not $version" >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    if [ "$dry_run" -eq 1 ]; then
        echo "warning: working tree has uncommitted changes; a real release requires a clean tree" >&2
    else
        echo "error: working tree has uncommitted changes; commit the release state first" >&2
        exit 1
    fi
fi

git fetch origin master --tags

head_sha="$(git rev-parse HEAD)"
origin_master_sha="$(git rev-parse origin/master)"
release_sha="$head_sha"
if [ "$head_sha" != "$origin_master_sha" ]; then
    if [ "$dry_run" -eq 1 ]; then
        echo "warning: HEAD does not match origin/master; a real release tags origin/master" >&2
        echo "         HEAD:          $head_sha" >&2
        echo "         origin/master: $origin_master_sha" >&2
        release_sha="$origin_master_sha"
    else
        echo "error: HEAD must match origin/master before cutting a dm-agent release" >&2
        echo "       HEAD:          $head_sha" >&2
        echo "       origin/master: $origin_master_sha" >&2
        exit 1
    fi
fi

tag="dm-agent-v$version"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "error: local tag already exists: $tag" >&2
    exit 1
fi

if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    echo "error: remote tag already exists: $tag" >&2
    exit 1
fi

echo "dm-agent release:"
echo "  tag:     $tag"
echo "  commit:  $release_sha"
echo "  version: $version"

if [ "$dry_run" -eq 1 ]; then
    echo "[dry-run] git tag -a $tag -m \"DM Agent v$version\" $release_sha"
    if [ "$push" -eq 1 ]; then
        echo "[dry-run] git push origin $tag"
    fi
    exit 0
fi

git tag -a "$tag" -m "DM Agent v$version" "$release_sha"

if [ "$push" -eq 1 ]; then
    git push origin "$tag"
    echo "pushed $tag; GitHub Actions will publish the DM Agent release"
else
    echo "created local tag $tag; push with: git push origin $tag"
fi
