#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: cut-full-release.sh [options] <version>

Create the full MDK release cohort:
  - v<version> source release
  - wn-agent-v<version> binary/adapter release
  - marmotkit-v<version> generated bindings release

By default this pushes all tags, creates the MDK source release with generated
GitHub notes, waits for the WN Agent and MarmotKit workflows, verifies the
resulting releases, and marks the MDK source release as Latest.

Options:
  --draft      Create GitHub Releases as drafts for manual publish. Artifact
               workflows upload into the draft releases and leave them draft.
  --dry-run    Print the actions without creating tags, releases, or pushes.
  --no-push    Create local tags only; do not push tags or create releases.
  --no-wait    Do not wait for tag-triggered artifact workflows.
  --repo REPO  GitHub repository, in OWNER/NAME form (default: marmot-protocol/mdk).
  -h, --help   Show this help.

Examples:
  ./scripts/cut-full-release.sh 0.9.3
  ./scripts/cut-full-release.sh --draft 0.9.3
  ./scripts/cut-full-release.sh --dry-run 0.9.3
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    if [ "$dry_run" -eq 0 ]; then
        "$@"
    fi
}

semver_like='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
repo="${GH_REPO:-marmot-protocol/mdk}"
version=""
draft=0
dry_run=0
push=1
wait=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --draft)
            draft=1
            shift
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --no-push)
            push=0
            wait=0
            shift
            ;;
        --no-wait)
            wait=0
            shift
            ;;
        --repo)
            [ "$#" -ge 2 ] || die "--repo requires OWNER/NAME"
            repo="$2"
            shift 2
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

[ -n "$version" ] || die "version is required"
[[ "$version" =~ $semver_like ]] || die "version must be semver-like, for example 0.9.3 or 0.9.3-alpha.1"

command -v git >/dev/null || die "git not found on PATH"
if [ "$push" -eq 1 ]; then
    command -v gh >/dev/null || die "gh not found on PATH"
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
[ "$workspace_version" = "$version" ] || die "Cargo.toml workspace version is $workspace_version, not $version"

if [ -n "$(git status --porcelain)" ]; then
    if [ "$dry_run" -eq 1 ]; then
        echo "warning: working tree has uncommitted changes; a real release requires a clean tree" >&2
    else
        die "working tree has uncommitted changes; commit the release state first"
    fi
fi

run git fetch origin master --tags

head_sha="$(git rev-parse HEAD)"
origin_master_sha="$(git rev-parse origin/master)"
release_sha="$origin_master_sha"
if [ "$head_sha" != "$origin_master_sha" ]; then
    if [ "$dry_run" -eq 1 ]; then
        echo "warning: HEAD does not match origin/master; a real release tags origin/master" >&2
        echo "         HEAD:          $head_sha" >&2
        echo "         origin/master: $origin_master_sha" >&2
    else
        echo "HEAD:          $head_sha" >&2
        echo "origin/master: $origin_master_sha" >&2
        die "HEAD must match origin/master before cutting a full release"
    fi
fi

if [ "$push" -eq 1 ] && [ "$dry_run" -eq 0 ]; then
    gh auth status -h github.com >/dev/null || die "gh is not authenticated for github.com"
fi

mdk_tag="v$version"
wn_tag="wn-agent-v$version"
marmotkit_tag="marmotkit-v$version"

previous_tag() {
    local pattern="$1"
    local current="$2"
    git tag -l "$pattern" --sort=-v:refname | awk -v current="$current" '$0 != current { print; exit }'
}

previous_mdk_tag="$(previous_tag 'v[0-9]*' "$mdk_tag")"
previous_wn_tag="$(previous_tag 'wn-agent-v[0-9]*' "$wn_tag")"
previous_marmotkit_tag="$(previous_tag 'marmotkit-v[0-9]*' "$marmotkit_tag")"

check_tag_available() {
    local tag="$1"
    if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        if [ "$dry_run" -eq 1 ]; then
            echo "warning: local tag already exists: $tag" >&2
            return
        fi
        die "local tag already exists: $tag"
    fi
    if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
        if [ "$dry_run" -eq 1 ]; then
            echo "warning: remote tag already exists: $tag" >&2
            return
        fi
        die "remote tag already exists: $tag"
    fi
    if [ "$push" -eq 1 ] && [ "$dry_run" -eq 0 ] && gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
        die "GitHub Release already exists: $tag"
    fi
}

check_tag_available "$mdk_tag"
check_tag_available "$wn_tag"
check_tag_available "$marmotkit_tag"

create_tag() {
    local tag="$1"
    local message="$2"
    run git tag -a "$tag" -m "$message" "$release_sha"
}

push_tag() {
    local tag="$1"
    if [ "$push" -eq 0 ]; then
        echo "created local tag $tag; push with: git push origin $tag"
        return
    fi
    run git push origin "$tag"
}

verify_remote_tag() {
    local tag="$1"

    if [ "$dry_run" -eq 1 ] || [ "$push" -eq 0 ]; then
        return
    fi

    local remote_sha
    remote_sha="$(git ls-remote --tags origin "refs/tags/$tag^{}" | awk '{print $1}')"
    [ "$remote_sha" = "$release_sha" ] || die "$tag dereferences to ${remote_sha:-missing}, expected $release_sha"
    echo "verified remote tag $tag -> $remote_sha"
}

create_generated_release() {
    local tag="$1"
    local title="$2"
    local previous="$3"
    local prerelease="$4"
    local latest="$5"
    local args=(release create "$tag" --repo "$repo" --verify-tag --title "$title" --generate-notes)

    if [ -n "$previous" ]; then
        args+=(--notes-start-tag "$previous")
    fi
    if [ "$draft" -eq 1 ]; then
        args+=(--draft)
    fi
    if [ "$prerelease" -eq 1 ]; then
        args+=(--prerelease)
    fi
    case "$latest" in
        true)
            args+=(--latest)
            ;;
        false)
            args+=(--latest=false)
            ;;
        auto)
            ;;
        *)
            die "unknown latest mode: $latest"
            ;;
    esac

    run gh "${args[@]}"
}

find_run_id() {
    local workflow="$1"
    local ref="$2"
    gh run list \
        --repo "$repo" \
        --workflow "$workflow" \
        --branch "$ref" \
        --event push \
        --json databaseId,headSha \
        --jq ".[] | select(.headSha == \"$release_sha\") | .databaseId" \
        --limit 10 |
        head -n 1
}

wait_for_workflow() {
    local workflow="$1"
    local ref="$2"
    local run_id=""

    if [ "$dry_run" -eq 1 ]; then
        echo "[dry-run] wait for workflow '$workflow' on $ref"
        return
    fi

    echo "waiting for workflow '$workflow' on $ref..."
    for _ in $(seq 1 60); do
        run_id="$(find_run_id "$workflow" "$ref")"
        if [ -n "$run_id" ]; then
            break
        fi
        sleep 5
    done

    [ -n "$run_id" ] || die "could not find workflow run for '$workflow' on $ref"
    run gh run watch "$run_id" --repo "$repo" --exit-status
}

verify_release() {
    local tag="$1"
    local expected_title="$2"
    local expected_draft="$3"
    local expected_prerelease="$4"
    local min_assets="$5"

    if [ "$dry_run" -eq 1 ] || [ "$push" -eq 0 ]; then
        return
    fi

    local release_info
    release_info="$(
        gh release view "$tag" \
            --repo "$repo" \
            --json name,isDraft,isPrerelease,assets \
            --jq '[.name, (.isDraft | tostring), (.isPrerelease | tostring), (.assets | length | tostring)] | @tsv'
    )"

    local title is_draft is_prerelease asset_count
    IFS=$'\t' read -r title is_draft is_prerelease asset_count <<<"$release_info"

    [ "$title" = "$expected_title" ] || die "$tag title is '$title', expected '$expected_title'"
    [ "$is_draft" = "$expected_draft" ] || die "$tag draft state is $is_draft, expected $expected_draft"
    [ "$is_prerelease" = "$expected_prerelease" ] || die "$tag prerelease state is $is_prerelease, expected $expected_prerelease"
    if [ "$asset_count" -lt "$min_assets" ]; then
        die "$tag has $asset_count assets, expected at least $min_assets"
    fi

    echo "verified $tag: title='$title', draft=$is_draft, prerelease=$is_prerelease, assets=$asset_count"
}

echo "full MDK release:"
echo "  repo:       $repo"
echo "  version:    $version"
echo "  commit:     $release_sha"
echo "  mode:       $([ "$draft" -eq 1 ] && echo draft || echo publish)"
echo "  wait:       $([ "$wait" -eq 1 ] && echo yes || echo no)"
echo "  tags:       $mdk_tag, $wn_tag, $marmotkit_tag"
echo "  previous:   ${previous_mdk_tag:-none}, ${previous_wn_tag:-none}, ${previous_marmotkit_tag:-none}"

create_tag "$mdk_tag" "mdk v$version"
create_tag "$wn_tag" "WN Agent v$version"
create_tag "$marmotkit_tag" "MarmotKit v$version"

push_tag "$mdk_tag"
verify_remote_tag "$mdk_tag"
if [ "$push" -eq 1 ]; then
    create_generated_release "$mdk_tag" "v$version - MDK" "$previous_mdk_tag" 0 "$([ "$draft" -eq 1 ] && echo false || echo true)"
fi

push_tag "$wn_tag"
verify_remote_tag "$wn_tag"
if [ "$push" -eq 1 ] && [ "$draft" -eq 1 ]; then
    create_generated_release "$wn_tag" "v$version - wn-agent" "$previous_wn_tag" 1 false
fi

push_tag "$marmotkit_tag"
verify_remote_tag "$marmotkit_tag"
if [ "$push" -eq 1 ] && [ "$draft" -eq 1 ]; then
    create_generated_release "$marmotkit_tag" "v$version - MarmotKit" "$previous_marmotkit_tag" 0 false
fi

if [ "$push" -eq 1 ] && [ "$wait" -eq 1 ]; then
    wait_for_workflow "wn-agent Binaries" "$wn_tag"
    wait_for_workflow "MarmotKit Bindings" "$marmotkit_tag"

    if [ "$draft" -eq 0 ]; then
        run gh release edit "$mdk_tag" --repo "$repo" --latest
    fi

    verify_release "$mdk_tag" "v$version - MDK" "$([ "$draft" -eq 1 ] && echo true || echo false)" false 0
    verify_release "$wn_tag" "v$version - wn-agent" "$([ "$draft" -eq 1 ] && echo true || echo false)" true 14
    if [ "$draft" -eq 0 ]; then
        verify_release "wn-agent-latest" "Latest WN Agent installers" false true 3
    fi
    verify_release "$marmotkit_tag" "v$version - MarmotKit" "$([ "$draft" -eq 1 ] && echo true || echo false)" false 4
elif [ "$push" -eq 1 ]; then
    echo "pushed release tags; artifact workflows will finish asynchronously"
    if [ "$draft" -eq 0 ]; then
        echo "after artifact workflows finish, run: gh release edit $mdk_tag --repo $repo --latest"
    fi
fi

echo "release cohort started for $version"
