#!/usr/bin/env python3
"""Promote a verified SemVer RC to a formal MDK Stable cohort release.

Used by `.github/workflows/promote-release.yml` and `just promote-rc`.
Verifies that the named RC (`X.Y.Z-rc.N`) was published atomically from an
exact `source_sha` reachable from `origin/master`, stamps ONLY release metadata
onto `source_sha` (enforcing a fail-closed metadata-only diff guard with zero
code edits and zero test re-runs), publishes all four tracks (`vX.Y.Z`,
`marmotkit-vX.Y.Z`, `marmotc-vX.Y.Z`, `wn-agent-vX.Y.Z`), records
`stable/latest.json` on `rc-meta`, and opens a signed docs/next-dev sync PR
back to `master`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import changelog  # noqa: E402
import classify_release_impact as impact_classifier  # noqa: E402
import rc_release  # noqa: E402

STABLE_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
VECTOR_PATH_RE = re.compile(r"^crates/cgka-conformance-simulator/vectors/.*\.json$")
CHANGELOG_PATH_RE = re.compile(r"^(?:.*/)?CHANGELOG\.md$")
FRAGMENT_PATH_RE = re.compile(r"^(?:.*/)?changelog\.d/[^/]+\.md$")
RELEASE_DOC_RE = re.compile(r"^docs/(?:release|integration)/\d+\.\d+\.\d+\.md$")
INSTALL_PIN_READMES = frozenset({
    "README.md",
    "release.md",
    "docs/integration/README.md",
    "integrations/README.md",
    "integrations/claude/marmot/README.md",
    "integrations/codex/marmot/README.md",
    "integrations/goose/marmot/README.md",
    "integrations/hermes/marmot/README.md",
    "integrations/openclaw/marmot/README.md",
    "integrations/opencode/marmot/README.md",
    "integrations/pi/marmot/README.md",
})
INSTALLER_HELP_PIN_FILES = frozenset({
    "scripts/install-hermes-marmot.sh",
    "scripts/install-openclaw-marmot.sh",
})
INSTALLER_PIN_LINE_RE = re.compile(
    r"^[+-]  base_url=https://github\.com/marmot-protocol/mdk/releases/download/wn-agent-v\d+\.\d+\.\d+$"
)
EXACT_METADATA_PATHS = frozenset({"Cargo.toml", "Cargo.lock"}) | INSTALL_PIN_READMES | INSTALLER_HELP_PIN_FILES


class PromoteError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def next_dev_version_after(stable_version: str, current_master_workspace_version: str) -> str:
    """Compute master's post-release `-dev` version after shipping `stable_version`."""
    s_match = STABLE_VERSION_RE.fullmatch(stable_version)
    if not s_match:
        raise PromoteError(f"invalid stable version: {stable_version}")
    s_major, s_minor, s_patch = (int(g) for g in s_match.groups())
    dev_tuple = rc_release.dev_base_version(current_master_workspace_version)
    # A minor release (0.20.0) advances master to 0.21.0-dev; a patch release (0.19.1)
    # keeps master on 0.20.0-dev when master is already ahead.
    candidate = (s_major, s_minor + 1, 0)
    if dev_tuple is not None and dev_tuple >= candidate:
        return current_master_workspace_version
    return f"{candidate[0]}.{candidate[1]}.{candidate[2]}-dev"


def is_allowed_metadata_path(rel_path: str) -> bool:
    return (
        rel_path in EXACT_METADATA_PATHS
        or bool(VECTOR_PATH_RE.fullmatch(rel_path))
        or bool(CHANGELOG_PATH_RE.fullmatch(rel_path))
        or bool(FRAGMENT_PATH_RE.fullmatch(rel_path))
        or bool(RELEASE_DOC_RE.fullmatch(rel_path))
    )


def verify_metadata_only_diff(root: Path, base_ref: str, head_ref: str | None = None) -> list[str]:
    """Fail closed if any changed path or installer script line falls outside release metadata."""
    diff_range = [base_ref] if head_ref is None else [base_ref, head_ref]
    raw_names = _git(root, "diff", "--no-renames", "--name-only", "-z", *diff_range)
    changed = [p for p in raw_names.split("\0") if p]
    if head_ref is None:
        untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
        changed = sorted(set(changed) | {p for p in untracked.split("\0") if p})

    errors: list[str] = []
    for rel_path in changed:
        if not is_allowed_metadata_path(rel_path):
            errors.append(f"disallowed non-metadata file modified: {rel_path}")
            continue
        if rel_path in INSTALLER_HELP_PIN_FILES:
            patch = _git(root, "diff", "--unified=0", *diff_range, "--", rel_path)
            content_changes = [
                line
                for line in patch.splitlines()
                if (line.startswith("+") or line.startswith("-"))
                and not line.startswith("+++")
                and not line.startswith("---")
            ]
            if not content_changes or any(not INSTALLER_PIN_LINE_RE.fullmatch(line) for line in content_changes):
                errors.append(
                    f"{rel_path}: only the pinned release base_url help comment may change during promotion"
                )
    return errors


def _workspace_package_names(root: Path) -> set[str]:
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = cargo.get("workspace", {}).get("members", [])
    names: set[str] = set()
    for member in members:
        manifest = root / member / "Cargo.toml"
        if not manifest.is_file():
            continue
        pkg = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
        if pkg.get("name"):
            names.add(str(pkg["name"]))
    return names


def stamp_workspace_version(root: Path, new_version: str) -> None:
    """Update workspace version in `Cargo.toml`, workspace entries in `Cargo.lock`, and vectors."""
    cargo_path = root / "Cargo.toml"
    cargo_text = cargo_path.read_text(encoding="utf-8")
    updated_cargo, count = re.subn(
        r'(?m)^(\[workspace\.package\]\n(?:[^\[]*\n)*?version = ")([^"]+)(")',
        lambda m: f"{m.group(1)}{new_version}{m.group(3)}",
        cargo_text,
        count=1,
    )
    if count != 1:
        raise PromoteError("could not locate [workspace.package] version in Cargo.toml")
    cargo_path.write_text(updated_cargo, encoding="utf-8")

    ws_names = _workspace_package_names(root)
    lock_path = root / "Cargo.lock"
    if lock_path.is_file() and ws_names:
        blocks = lock_path.read_text(encoding="utf-8").split("\n[[package]]\n")
        for idx in range(1, len(blocks)):
            block = blocks[idx]
            name_match = re.search(r'(?m)^name = "([^"]+)"$', block)
            if name_match and name_match.group(1) in ws_names:
                blocks[idx] = re.sub(
                    r'(?m)^version = "[^"]+"$',
                    f'version = "{new_version}"',
                    block,
                    count=1,
                )
        lock_path.write_text("\n[[package]]\n".join(blocks), encoding="utf-8")

    vectors_root = root / "crates/cgka-conformance-simulator/vectors"
    if vectors_root.is_dir():
        for vec_path in sorted(vectors_root.rglob("*.json")):
            raw = vec_path.read_text(encoding="utf-8")
            updated = re.sub(
                r'("conformance_version"\s*:\s*")[^"]+(")',
                lambda m: f"{m.group(1)}{new_version}{m.group(2)}",
                raw,
            )
            if updated != raw:
                vec_path.write_text(updated, encoding="utf-8")


def stamp_install_pins_and_docs(
    root: Path,
    *,
    stable_version: str,
    baseline_version: str,
    report: dict[str, Any],
    delta: dict[str, Any],
) -> None:
    """Write `docs/release/<v>.md`, `docs/integration/<v>.md`, index links, and installer pins."""
    release_doc = root / "docs/release" / f"{stable_version}.md"
    integration_doc = root / "docs/integration" / f"{stable_version}.md"
    release_doc.parent.mkdir(parents=True, exist_ok=True)
    integration_doc.parent.mkdir(parents=True, exist_ok=True)

    release_doc.write_text(
        impact_classifier.render_release_notes(
            report,
            delta,
            version=stable_version,
            integration_guide_link=f"../integration/{stable_version}.md",
        ),
        encoding="utf-8",
    )
    prev_guide_link = f"{baseline_version}.md" if (root / "docs/integration" / f"{baseline_version}.md").is_file() else None
    integration_doc.write_text(
        impact_classifier.render_integration_notes(
            report,
            delta,
            version_label=stable_version,
            release_notes_link=f"../release/{stable_version}.md",
            previous_guide_link=prev_guide_link,
        ),
        encoding="utf-8",
    )

    # Prepend row in docs/integration/README.md if not already present.
    index_path = root / "docs/integration/README.md"
    if index_path.is_file():
        index_text = index_path.read_text(encoding="utf-8")
        row = f"| {baseline_version} → {stable_version} | [{stable_version} integration]({stable_version}.md) | [{stable_version} notes](../release/{stable_version}.md) |"
        if row not in index_text:
            updated = re.sub(
                r"(\| --- \| --- \| --- \|\n)",
                lambda m: m.group(1) + row + "\n",
                index_text,
                count=1,
            )
            index_path.write_text(updated, encoding="utf-8")

    # Update root README.md latest upgrade guide link.
    readme_path = root / "README.md"
    if readme_path.is_file():
        readme_text = readme_path.read_text(encoding="utf-8")
        updated_readme = re.sub(
            r"The latest is \[\d+\.\d+\.\d+ → \d+\.\d+\.\d+\]\(docs/integration/\d+\.\d+\.\d+\.md\)",
            f"The latest is [{baseline_version} → {stable_version}](docs/integration/{stable_version}.md)",
            readme_text,
            count=1,
        )
        readme_path.write_text(updated_readme, encoding="utf-8")

    # Update immutable wn-agent-v<version> base_url pins in release.md, integrations/**/README.md,
    # and the two verified-download comments in install-{hermes,openclaw}-marmot.sh.
    pin_re = re.compile(
        r"(https://github\.com/marmot-protocol/mdk/releases/download/wn-agent-v)\d+\.\d+\.\d+"
    )
    for rel in sorted(INSTALL_PIN_READMES | INSTALLER_HELP_PIN_FILES):
        if rel in {"README.md", "docs/integration/README.md"}:
            continue
        path = root / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        updated = pin_re.sub(lambda m: f"{m.group(1)}{stable_version}", text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def verify_rc_evidence(gh: rc_release.GitHub, rc_version: str) -> dict[str, Any]:
    """Load RC metadata from `rc-meta` and verify all three published immutable RC tracks."""
    if rc_release.RC_VERSION.fullmatch(rc_version) is None:
        raise PromoteError(f"invalid rc_version {rc_version!r}; expected X.Y.Z-rc.N")

    record = gh.read_meta_json(f"{rc_release.RC_RELEASES_DIR}/{rc_version}.json")
    if record is None:
        latest = gh.read_latest_rc()
        if latest and latest.get("version") == rc_version:
            record = latest
    if record is None:
        raise PromoteError(f"RC {rc_version} was not found on {rc_release.META_BRANCH}")

    source_sha = record.get("source_sha", "")
    if not rc_release.FULL_SHA.fullmatch(source_sha):
        raise PromoteError(f"RC {rc_version} has invalid source_sha: {source_sha!r}")

    for prefix, title in rc_release.TRACKS:
        tag = f"{prefix}-v{rc_version}"
        rel = gh.release_for_tag(tag)
        if rel is None or rel["draft"] or not rel["prerelease"] or rel.get("immutable") is not True:
            raise PromoteError(f"RC track {tag} is not a published immutable pre-release")
        if rel["name"] != f"v{rc_version} - {title}":
            raise PromoteError(f"RC track {tag} has unexpected title {rel['name']!r}")
        tag_sha = gh.tag_commit(tag)
        if tag_sha != source_sha:
            raise PromoteError(f"RC track {tag} points to {tag_sha}, expected {source_sha}")
    return record


def command_plan(args: argparse.Namespace) -> int:
    gh = rc_release.github_from_env()
    root = Path(args.root).resolve()
    record = verify_rc_evidence(gh, args.rc_version)
    source_sha = record["source_sha"]

    # Confirm source_sha is reachable from origin/master.
    probe = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", source_sha, args.master_ref],
        capture_output=True,
    )
    if probe.returncode != 0:
        raise PromoteError(f"RC source commit {source_sha} is not reachable from {args.master_ref}")

    stable_version = (args.override_version or "").strip() or rc_release.rc_base_version(args.rc_version)
    if STABLE_VERSION_RE.fullmatch(stable_version) is None:
        raise PromoteError(f"stable version must be X.Y.Z, got {stable_version!r}")

    # Refuse if any formal tag already exists.
    all_tags = [f"v{stable_version}", *rc_release.track_tags(stable_version, allow_stable=True).values()]
    for tag in all_tags:
        if gh.tag_commit(tag) is not None:
            raise PromoteError(f"formal release tag {tag} already exists")
        existing = gh.release_for_tag(tag)
        if existing is not None and not existing["draft"]:
            raise PromoteError(f"published GitHub Release already exists for {tag}")

    master_ws = tomllib.loads(_git(root, "show", f"{args.master_ref}:Cargo.toml"))["workspace"]["package"][
        "version"
    ]
    next_dev = next_dev_version_after(stable_version, master_ws)
    baseline_tag = record.get("baseline_tag") or ""
    if not baseline_tag:
        baseline_tag, _ = impact_classifier.find_latest_stable_tag(root, source_sha)

    rc_release.write_outputs({
        "rc_version": args.rc_version,
        "stable_version": stable_version,
        "source_sha": source_sha,
        "baseline_tag": baseline_tag,
        "next_dev_version": next_dev,
        "release_branch": f"release/v{stable_version}",
    })
    rc_release.write_summary("\n".join([
        "## Stable promotion plan",
        "",
        f"- Verified RC: `{args.rc_version}`",
        f"- Exact RC `source_sha`: `{source_sha}`",
        f"- Target Stable version: `{stable_version}` (override: `{args.override_version or 'none'}`)",
        f"- Baseline stable tag: `{baseline_tag}`",
        f"- Post-release master `-dev` version: `{next_dev}`",
    ]))
    return 0


def command_stamp(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    version = args.version
    if STABLE_VERSION_RE.fullmatch(version) is None:
        raise PromoteError(f"invalid stable version: {version}")
    day = args.date or dt.datetime.now(dt.timezone.utc).date().isoformat()

    report, delta = impact_classifier.classify_range(
        root,
        baseline_ref=args.baseline_ref or None,
        target_ref="HEAD",
    )

    # Fold changelog.d/ fragments before mutating Cargo.toml (changelog.release reads HEAD).
    cl_errors = changelog.release(root, version, day)
    if cl_errors:
        raise PromoteError("changelog fold failed: " + "; ".join(cl_errors))

    stamp_workspace_version(root, version)
    stamp_install_pins_and_docs(
        root,
        stable_version=version,
        baseline_version=report["baseline_version"],
        report=report,
        delta=delta,
    )

    diff_errors = verify_metadata_only_diff(root, "HEAD")
    if diff_errors:
        raise PromoteError("metadata-only diff guard failed: " + "; ".join(diff_errors))
    print(f"stamped release metadata for {version} cleanly")
    return 0


def command_verify_metadata_diff(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    errors = verify_metadata_only_diff(root, args.base, args.head)
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1
    print(f"metadata-only diff verified ({args.base}..{args.head or 'WORKTREE'})")
    return 0


def create_signed_commit_from_worktree(
    gh: rc_release.GitHub,
    root: Path,
    *,
    parent_sha: str,
    branch: str,
    message: str,
) -> str:
    """Create a GitHub-API-signed commit on `branch` reflecting the worktree diff over `parent_sha`."""
    head_sha = _git(root, "rev-parse", "HEAD").strip()
    if head_sha != parent_sha:
        raise PromoteError(
            f"worktree HEAD {head_sha} does not match expected parent_sha {parent_sha}; "
            "refusing to commit drifted tree"
        )
    status_out = _git(root, "diff", "--no-renames", "--name-status", "-z", parent_sha)
    tokens = status_out.split("\0")
    entries: list[dict[str, Any]] = []
    idx = 0
    while idx < len(tokens) and tokens[idx]:
        code = tokens[idx]
        path = tokens[idx + 1]
        idx += 2
        if code.startswith("D"):
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
        else:
            full = root / path
            mode = "100755" if os.access(full, os.X_OK) else "100644"
            blob, _ = gh.request(
                "POST",
                gh.repo("git/blobs"),
                {"content": full.read_text(encoding="utf-8"), "encoding": "utf-8"},
            )
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})

    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    for path in (p for p in untracked.split("\0") if p):
        full = root / path
        mode = "100755" if os.access(full, os.X_OK) else "100644"
        blob, _ = gh.request(
            "POST",
            gh.repo("git/blobs"),
            {"content": full.read_text(encoding="utf-8"), "encoding": "utf-8"},
        )
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})

    if not entries:
        raise PromoteError("no metadata changes to commit")

    parent_commit = gh.get(gh.repo(f"git/commits/{parent_sha}"))
    tree, _ = gh.request(
        "POST",
        gh.repo("git/trees"),
        {"base_tree": parent_commit["tree"]["sha"], "tree": entries},
    )
    commit, _ = gh.request(
        "POST",
        gh.repo("git/commits"),
        {"message": message, "tree": tree["sha"], "parents": [parent_sha]},
    )
    verification = commit.get("verification") or {}
    if verification.get("verified") is not True:
        raise PromoteError(f"GitHub-signed commit {commit['sha']} failed verification: {verification}")

    ref = gh.get(gh.repo(f"git/ref/heads/{branch}"), allow_404=True)
    if ref is None:
        gh.request("POST", gh.repo("git/refs"), {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
    else:
        gh.request("PATCH", gh.repo(f"git/refs/heads/{branch}"), {"sha": commit["sha"], "force": True})
    return commit["sha"]


def command_commit_branch(args: argparse.Namespace) -> int:
    gh = rc_release.github_from_env()
    root = Path(args.root).resolve()
    errors = verify_metadata_only_diff(root, args.parent_sha)
    if errors:
        raise PromoteError("metadata-only diff guard failed: " + "; ".join(errors))
    sha = create_signed_commit_from_worktree(
        gh,
        root,
        parent_sha=args.parent_sha,
        branch=args.branch,
        message=args.message,
    )
    rc_release.write_outputs({"release_commit_sha": sha})
    print(f"created signed release commit {sha} on {args.branch}")
    return 0


def command_publish_stable(args: argparse.Namespace) -> int:
    gh = rc_release.github_from_env()
    version = args.version
    release_sha = args.release_sha
    if STABLE_VERSION_RE.fullmatch(version) is None:
        raise PromoteError(f"invalid stable version: {version}")
    if not rc_release.FULL_SHA.fullmatch(release_sha):
        raise PromoteError("--release-sha must be a full 40-character SHA")

    tags = rc_release.track_tags(version, allow_stable=True)
    titles = dict(rc_release.TRACKS)
    staged = {prefix: gh.release_for_tag(tag) for prefix, tag in tags.items()}
    for prefix, tag in tags.items():
        rc_release.check_staged_release(
            gh,
            staged[prefix],
            tag,
            f"v{version} - {titles[prefix]}",
            release_sha,
            expect_prerelease=(prefix == "wn-agent"),
        )

    mdk_tag = f"v{version}"
    mdk_notes = Path(args.notes_file).read_text(encoding="utf-8")
    existing_mdk = gh.release_for_tag(mdk_tag)
    if existing_mdk is not None:
        if existing_mdk["draft"]:
            if existing_mdk.get("target_commitish") != release_sha:
                raise PromoteError(
                    f"{mdk_tag} draft targets {existing_mdk.get('target_commitish')}, expected {release_sha}"
                )
        elif gh.tag_commit(mdk_tag) != release_sha:
            raise PromoteError(f"{mdk_tag} already exists on a different commit")
    else:
        existing_mdk_tag_sha = gh.tag_commit(mdk_tag)
        if existing_mdk_tag_sha is not None and existing_mdk_tag_sha != release_sha:
            raise PromoteError(f"{mdk_tag} tag already exists on {existing_mdk_tag_sha}, expected {release_sha}")

    # Publish all three artifact tracks first, then publish the whole-workspace `v<version>` as Latest.
    releases: dict[str, dict[str, Any]] = {}
    for prefix, tag in tags.items():
        releases[prefix] = rc_release.publish_release(
            gh,
            staged[prefix],
            tag,
            release_sha,
            prerelease=(prefix == "wn-agent"),
            make_latest="false",
        )

    if existing_mdk is None:
        mdk_rel, _ = gh.request("POST", gh.repo("releases"), {
            "tag_name": mdk_tag,
            "target_commitish": release_sha,
            "name": f"v{version} - MDK",
            "body": mdk_notes,
            "draft": False,
            "prerelease": False,
            "make_latest": "true",
        })
    elif existing_mdk["draft"]:
        mdk_rel = rc_release.publish_release(
            gh, existing_mdk, mdk_tag, release_sha, prerelease=False, make_latest="true"
        )
    else:
        mdk_rel = existing_mdk

    tracks_doc: dict[str, Any] = {
        "mdk": {
            "tag": mdk_tag,
            "release_url": f"https://github.com/{gh.repository}/releases/tag/{mdk_tag}",
            "assets": [],
        }
    }
    for prefix, tag in tags.items():
        assets = []
        for asset in sorted(releases[prefix]["assets"], key=lambda item: item["name"]):
            digest = asset.get("digest") or ""
            assets.append({
                "name": asset["name"],
                "url": f"https://github.com/{gh.repository}/releases/download/{tag}/{asset['name']}",
                "sha256": digest.removeprefix("sha256:"),
                "size": asset["size"],
            })
        tracks_doc[prefix] = {
            "tag": tag,
            "release_url": f"https://github.com/{gh.repository}/releases/tag/{tag}",
            "assets": assets,
        }

    stable_doc = {
        "schema": 2,
        "channel": "stable",
        "version": version,
        "promoted_from_rc": args.rc_version,
        "source_sha": args.rc_source_sha,
        "release_sha": release_sha,
        "date": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "workflow_run": rc_release.run_url(),
        "tracks": tracks_doc,
    }
    meta_token = os.environ.get("META_GH_TOKEN")
    meta_gh = rc_release.GitHub(gh.repository, meta_token, gh.api_url) if meta_token else gh
    meta_sha = rc_release.write_meta_files(
        meta_gh,
        {rc_release.STABLE_LATEST_FILE: json.dumps(stable_doc, indent=2, sort_keys=True) + "\n"},
        f"Stable {version} promoted from {args.rc_version} ({release_sha})",
    )
    rc_release.write_summary("\n".join([
        f"## Stable release published (`v{version}`)",
        "",
        f"- [`{mdk_tag}`]({mdk_rel['html_url']})",
        *(
            f"- [`{tag}`](https://github.com/{gh.repository}/releases/tag/{tag})"
            for tag in tags.values()
        ),
        f"- `{rc_release.STABLE_LATEST_FILE}` on `{rc_release.META_BRANCH}`: verified commit `{meta_sha}`",
    ]))
    return 0


def apply_release_metadata_sync(
    root: Path,
    *,
    master_sha: str,
    rc_source_sha: str,
    release_sha: str,
    next_dev: str,
) -> None:
    """Apply release metadata onto exact `master_sha` with 3-way merge safety.

    Never overwrites concurrent edits on `master`, never removes fragments that
    changed after `rc_source_sha`, and enforces `verify_metadata_only_diff`
    before returning.
    """
    _git(root, "checkout", "--detach", "--force", master_sha)
    _git(root, "reset", "--hard", master_sha)
    _git(root, "clean", "-fd")

    raw_pairs = _git(root, "diff", "--no-renames", "--name-status", "-z", rc_source_sha, release_sha).split("\0")
    idx = 0
    while idx < len(raw_pairs) and raw_pairs[idx]:
        code = raw_pairs[idx]
        rel = raw_pairs[idx + 1]
        idx += 2
        if rel in {"Cargo.toml", "Cargo.lock"} or VECTOR_PATH_RE.fullmatch(rel):
            continue
        target = root / rel
        if code.startswith("D"):
            # Only delete a folded fragment if master has not modified it since rc_source_sha.
            if not target.exists():
                continue
            rc_blob = _git(root, "show", f"{rc_source_sha}:{rel}")
            master_blob = target.read_text(encoding="utf-8")
            if master_blob != rc_blob:
                raise PromoteError(
                    f"sync conflict: {rel} was modified on master after {rc_source_sha[:9]}; "
                    "resolve manually instead of discarding newer edits"
                )
            target.unlink()
        elif code.startswith("A"):
            new_content = _git(root, "show", f"{release_sha}:{rel}")
            if target.exists() and target.read_text(encoding="utf-8") != new_content:
                raise PromoteError(f"sync conflict: {rel} already exists on master with different content")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(new_content, encoding="utf-8")
        else:
            # Apply the exact metadata delta via three-way patch so concurrent edits
            # merged on master after rc_source_sha are preserved and conflicts fail closed.
            patch = _git(root, "diff", "--binary", rc_source_sha, release_sha, "--", rel)
            if not patch:
                continue
            proc = subprocess.run(
                ["git", "-C", str(root), "apply", "--3way", "--whitespace=nowarn", "-"],
                input=patch,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            if proc.returncode != 0:
                raise PromoteError(
                    f"sync conflict applying metadata delta to {rel} on {master_sha[:9]}: "
                    f"{(proc.stderr or proc.stdout).strip()}"
                )

    stamp_workspace_version(root, next_dev)
    errors = verify_metadata_only_diff(root, master_sha)
    if errors:
        raise PromoteError("metadata-only sync guard failed: " + "; ".join(errors))


def command_open_sync_pr(args: argparse.Namespace) -> int:
    """Open a signed docs/changelog/next-dev sync PR back to `master` after Stable promotion."""
    gh = rc_release.github_from_env()
    root = Path(args.root).resolve()
    version = args.version
    master_sha = _git(root, "rev-parse", f"{args.master_ref}^{{commit}}").strip()
    master_ws = tomllib.loads(_git(root, "show", f"{master_sha}:Cargo.toml"))["workspace"]["package"]["version"]
    next_dev = next_dev_version_after(version, master_ws)
    release_sha = args.release_sha

    apply_release_metadata_sync(
        root,
        master_sha=master_sha,
        rc_source_sha=args.rc_source_sha,
        release_sha=release_sha,
        next_dev=next_dev,
    )
    sync_branch = f"chore/release-sync-v{version}"
    msg = (
        f"Sync release metadata for v{version} and advance to {next_dev}\n\n"
        f"Promoted from verified RC `{args.rc_version}` (`{args.rc_source_sha[:9]}`).\n\n"
        f"Local-Checks: check_binding_docs --release-version {version}, changelog check, check_agent_install_docs, check_install_example_sha256\n"
        f"Local-Review: exempt (automated promotion from verified RC {args.rc_version})\n"
        f"Release-Impact: none\n"
    )
    commit_sha = create_signed_commit_from_worktree(
        gh,
        root,
        parent_sha=master_sha,
        branch=sync_branch,
        message=msg,
    )
    # Use PR_GH_TOKEN (e.g. RELEASE_TOKEN) when set so GitHub triggers pull_request CI checks
    # on the opened sync PR (PRs opened with GITHUB_TOKEN never start workflow runs).
    pr_token = os.environ.get("PR_GH_TOKEN")
    pr_gh = rc_release.GitHub(gh.repository, pr_token, gh.api_url) if pr_token else gh
    pr, _ = pr_gh.request("POST", pr_gh.repo("pulls"), {
        "title": f"Sync v{version} release docs and advance workspace to {next_dev}",
        "head": sync_branch,
        "base": "master",
        "body": (
            f"## Problem\n\n"
            f"`v{version}` was promoted from verified RC `{args.rc_version}` (`{args.rc_source_sha}`). "
            f"`master` needs the finalized release/integration docs, folded changelogs, updated install pins, "
            f"and `{next_dev}` development version.\n\n"
            f"## Fix\n\n"
            f"Automated metadata-only sync from release commit `{release_sha}`.\n"
        ),
    })
    print(f"opened docs-sync PR #{pr['number']}: {pr['html_url']} (commit {commit_sha})")
    rc_release.write_summary(f"- Docs & `{next_dev}` sync PR: [#{pr['number']}]({pr['html_url']})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="verify RC evidence and plan stable promotion")
    plan.add_argument("--root", default=".")
    plan.add_argument("--master-ref", default="origin/master")
    plan.add_argument("--rc-version", required=True)
    plan.add_argument("--override-version", default="")
    plan.set_defaults(func=command_plan)

    stamp = commands.add_parser("stamp", help="stamp release version, fold changelogs, and write docs")
    stamp.add_argument("--root", default=".")
    stamp.add_argument("--version", required=True)
    stamp.add_argument("--baseline-ref", default="")
    stamp.add_argument("--date", default="")
    stamp.set_defaults(func=command_stamp)

    verify = commands.add_parser("verify-metadata-diff", help="fail closed on any non-metadata diff")
    verify.add_argument("--root", default=".")
    verify.add_argument("--base", required=True)
    verify.add_argument("--head", default=None)
    verify.set_defaults(func=command_verify_metadata_diff)

    commit_cmd = commands.add_parser("commit-branch", help="push GitHub-signed release commit to branch")
    commit_cmd.add_argument("--root", default=".")
    commit_cmd.add_argument("--parent-sha", required=True)
    commit_cmd.add_argument("--branch", required=True)
    commit_cmd.add_argument("--message", required=True)
    commit_cmd.set_defaults(func=command_commit_branch)

    pub = commands.add_parser("publish-stable", help="publish stable cohort and update stable/latest.json")
    pub.add_argument("--version", required=True)
    pub.add_argument("--rc-version", required=True)
    pub.add_argument("--rc-source-sha", required=True)
    pub.add_argument("--release-sha", required=True)
    pub.add_argument("--notes-file", required=True)
    pub.set_defaults(func=command_publish_stable)

    sync = commands.add_parser("open-sync-pr", help="open docs/changelog/next-dev sync PR back to master")
    sync.add_argument("--root", default=".")
    sync.add_argument("--master-ref", default="origin/master")
    sync.add_argument("--version", required=True)
    sync.add_argument("--rc-version", required=True)
    sync.add_argument("--rc-source-sha", required=True)
    sync.add_argument("--release-sha", required=True)
    sync.add_argument("--next-dev-version", required=True)
    sync.set_defaults(func=command_open_sync_pr)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PromoteError, rc_release.ReleaseError, impact_classifier.ClassificationError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
