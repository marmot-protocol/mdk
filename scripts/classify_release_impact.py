#!/usr/bin/env python3
"""Three-layer SemVer Patch vs. Minor classifier for MDK daily RCs and releases.

Compares a verified target commit (typically `origin/canary`) against the latest
stable `vX.Y.Z` tag reachable from it using three independent layers (max-wins):

1. Mechanical ABI diff:
   - UniFFI exported callables (`check_binding_docs.uniffi_exports_in`) and
     `#[derive(... uniffi::Record | uniffi::Enum | uniffi::Error ...)]` types
     under `crates/marmot-uniffi/src/`.
   - C ABI functions (`check_binding_docs.c_exports_in`) and `struct` / `enum` /
     `typedef` declarations in `crates/marmot-c/include/marmot.h`.
   - Emits `signature_delta.json` and Markdown summaries for downstream White
     Noise client agents.
2. Mechanical storage-migration detector:
   - Any new or modified numbered SQLite migration under
     `crates/storage-sqlite/src/base/migrations/` (or `baseline.sql`) triggers
     `minor` because downgrade across schema migrations is unsupported.
3. Authored intent:
   - `Release-Impact: none | patch | minor` commit trailers across
     `baseline..target` (via `check_pr_trailers.extract_landed_trailers`).
   - Pending `changelog.d/*.md` fragments at `target` (`### Breaking changes`
     triggers `minor`; other sections trigger at least `patch`).

Before `1.0.0`, MDK treats `0.<minor>.0` as the breaking-compatibility line
(`minor`) and `0.<minor>.<patch>` as the compatible bugfix/additive line
(`patch`).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import changelog  # noqa: E402
import check_binding_docs  # noqa: E402
import check_c_binding_parity  # noqa: E402
import check_pr_trailers  # noqa: E402

IMPACT_RANK = {"none": 0, "patch": 1, "minor": 2}
STABLE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
STABLE_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
MIGRATION_FILE_RE = re.compile(
    r"^(?:"
    r"crates/storage-sqlite/src/base/migrations/(?:\d{4}_.*\.rs|baseline\.sql)"
    r"|crates/storage-sqlite/src/base/migrations\.rs"
    r"|crates/storage-sqlite/src/shared/migrations\.rs"
    r"|crates/nostr-directory/src/cache/migrations\.rs"
    r")$"
)
UNIFFI_DERIVE_RE = re.compile(
    r"#\[derive\((?P<derives>[^)]*\buniffi::(?:Record|Enum|Error)\b[^)]*)\)\]",
    re.DOTALL,
)
UNIFFI_TYPE_HEADER_RE = re.compile(
    r"(?:(?:#\[[^\]]*\]|///[^\n]*|//[^\n]*)\s*)*"
    r"pub(?:\([^)]*\))?\s+(?P<kind>struct|enum)\s+(?P<name>[A-Za-z_]\w*)[^{;]*(?P<delim>\{|;)",
    re.DOTALL,
)
C_TYPE_HEADER_RE = re.compile(
    r"(?m)^(?P<prefix>(?:typedef\s+)?(?:struct|enum)\s+[A-Za-z_]\w*)\s*"
    r"(?P<clause>(?:#if[\s\S]*?#endif[^\n]*\n\s*|:\s*[A-Za-z_]\w*\s*)?)\{",
)
C_TYPEDEF_ALIAS_RE = re.compile(r"(?m)^(typedef\s+[^;{}]+);")


class ClassificationError(RuntimeError):
    pass


def _max_impact(*impacts: str) -> str:
    return max(impacts, key=lambda item: IMPACT_RANK[item])


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git_stdout(root: Path, *args: str) -> str:
    return _git(root, *args, check=True).stdout


def resolve_commit(root: Path, ref: str) -> str:
    return git_stdout(root, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return _git(root, "merge-base", "--is-ancestor", ancestor, descendant, check=False).returncode == 0


def find_latest_stable_tag(root: Path, target_sha: str) -> tuple[str, str]:
    """Return `(tag_name, version)` for the highest applicable `vX.Y.Z` tag for `target_sha`.

    Matches both tags whose commit is a direct ancestor of `target_sha` (classic
    master releases) AND tags cut on a `release/vX.Y.Z` promotion branch whose
    first parent (`tag^1`, the verified RC `source_sha`) is an ancestor of
    `target_sha` (after a squash-merged docs-sync PR on `master`).
    """
    raw = git_stdout(root, "tag", "--list", "v*")
    candidates: list[tuple[tuple[int, int, int], str, str]] = []
    for line in raw.splitlines():
        tag = line.strip()
        match = STABLE_TAG_RE.fullmatch(tag)
        if not match:
            continue
        tag_commit = resolve_commit(root, tag)
        applicable = _is_ancestor(root, tag_commit, target_sha)
        if not applicable:
            parent_probe = _git(root, "rev-parse", "--verify", "--quiet", f"{tag_commit}^1", check=False)
            if parent_probe.returncode == 0:
                parent_sha = parent_probe.stdout.strip()
                applicable = bool(parent_sha) and _is_ancestor(root, parent_sha, target_sha)
        if not applicable:
            continue
        ver_tuple = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        candidates.append((ver_tuple, tag, f"{ver_tuple[0]}.{ver_tuple[1]}.{ver_tuple[2]}"))
    if not candidates:
        raise ClassificationError(
            f"no stable vX.Y.Z tag reachable from {target_sha}; fetch tags or pass --baseline-ref"
        )
    candidates.sort(key=lambda item: item[0])
    _, tag, version = candidates[-1]
    return tag, version


def next_base_version(baseline_version: str, impact: str) -> str:
    """Compute the target stable `X.Y.Z` version from `baseline_version` and `impact`."""
    match = STABLE_VERSION_RE.fullmatch(baseline_version)
    if not match:
        raise ClassificationError(f"baseline version must be X.Y.Z, got {baseline_version!r}")
    if impact not in IMPACT_RANK:
        raise ClassificationError(f"invalid impact {impact!r}")
    major, minor, patch = (int(g) for g in match.groups())
    if impact == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _strip_rust_comments(text: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", no_block)


def _strip_c_comments(text: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", lambda m: "\n" * m[0].count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", no_block)


def _normalize_ws(text: str) -> str:
    return " ".join(text.split())


def extract_uniffi_types_in(text: str, source: str) -> dict[str, dict[str, str]]:
    """Extract normalized UniFFI Record/Enum/Error definitions from Rust source."""
    types: dict[str, dict[str, str]] = {}
    for derive_match in UNIFFI_DERIVE_RE.finditer(text):
        tail = text[derive_match.end() :]
        header = UNIFFI_TYPE_HEADER_RE.match(tail.lstrip())
        if not header:
            continue
        leading_ws = len(tail) - len(tail.lstrip())
        abs_header_end = derive_match.end() + leading_ws + header.end()
        name = header.group("name")
        kind = header.group("kind")
        if header.group("delim") == "{":
            brace_idx = abs_header_end - 1
            body = check_c_binding_parity._braced_block(text, brace_idx)
            # Strip comments inside the body so doc-comment edits never register as ABI breaks.
            normalized_body = _normalize_ws(_strip_rust_comments(body))
            definition = f"pub {kind} {name} {{{normalized_body}}}"
        else:
            definition = _normalize_ws(_strip_rust_comments(header.group(0)))
        derives = sorted(
            part.strip()
            for part in derive_match.group("derives").split(",")
            if "uniffi::" in part
        )
        types[name] = {
            "kind": kind,
            "derives": ", ".join(derives),
            "definition": definition,
            "source": f"crates/marmot-uniffi/src/{source}",
        }
    return types


def extract_c_types_in(header: str) -> dict[str, str]:
    """Extract normalized C `struct`, `enum`, and `typedef` declarations from `marmot.h`."""
    clean = _strip_c_comments(header)
    types: dict[str, str] = {}
    for match in C_TYPE_HEADER_RE.finditer(clean):
        brace_idx = match.end() - 1
        try:
            body = check_c_binding_parity._braced_block(clean, brace_idx)
        except ValueError:
            continue
        end_idx = brace_idx + len(body) + 1
        semi_idx = clean.find(";", end_idx)
        suffix = clean[end_idx : semi_idx + 1] if semi_idx != -1 else ";"
        prefix = _normalize_ws(match.group("prefix"))
        clause = _normalize_ws(match.group("clause") or "")
        # Key by trailing typedef alias if present, else `struct Foo` / `enum Foo`.
        alias = _normalize_ws(suffix.rstrip(";").strip())
        key = alias if prefix.startswith("typedef ") and alias else prefix
        header_head = f"{prefix} {clause}" if clause else prefix
        types[key] = _normalize_ws(f"{header_head} {{{body}}} {suffix}")
    for match in C_TYPEDEF_ALIAS_RE.finditer(clean):
        decl = _normalize_ws(match.group(1))
        cb_match = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", decl)
        if cb_match:
            key = f"typedef {cb_match.group(1)}"
            types.setdefault(key, decl + ";")
            continue
        name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\([^)]*\))?$", decl)
        if name_match:
            key = f"typedef {name_match.group(1)}"
            types.setdefault(key, decl + ";")
    return types


def _read_tree_files(root: Path, sha: str, prefix: str, suffix: str) -> dict[str, str]:
    raw = _git(root, "ls-tree", "-r", "-z", "--name-only", sha, "--", prefix, check=False)
    if raw.returncode != 0:
        raise ClassificationError(f"failed to list {prefix} at {sha}: {raw.stderr.strip()}")
    files: dict[str, str] = {}
    for rel in raw.stdout.split("\0"):
        if not rel or not rel.endswith(suffix):
            continue
        blob = _git(root, "show", f"{sha}:{rel}", check=False)
        if blob.returncode != 0:
            raise ClassificationError(f"failed to read {rel} at {sha}: {blob.stderr.strip()}")
        files[rel] = blob.stdout
    return files


def _read_file_at(root: Path, sha: str, rel_path: str) -> str | None:
    listed = _git(root, "ls-tree", "-z", "--name-only", sha, "--", rel_path, check=False)
    if listed.returncode != 0:
        raise ClassificationError(f"failed to inspect {rel_path} at {sha}: {listed.stderr.strip()}")
    if not listed.stdout.strip("\0"):
        return None
    res = _git(root, "show", f"{sha}:{rel_path}", check=False)
    if res.returncode != 0:
        raise ClassificationError(f"failed to read {rel_path} at {sha}: {res.stderr.strip()}")
    return res.stdout


def extract_uniffi_surface(root: Path, sha: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Return `(callables, types)` exported by `crates/marmot-uniffi/src/` at `sha`."""
    prefix = "crates/marmot-uniffi/src/"
    files = _read_tree_files(root, sha, "crates/marmot-uniffi/src", ".rs")
    callables: dict[str, dict[str, str]] = {}
    types: dict[str, dict[str, str]] = {}
    for rel_path, content in sorted(files.items()):
        rel_src = rel_path.removeprefix(prefix)
        lines = content.splitlines()
        for key, export in check_binding_docs.uniffi_exports_in(content, rel_src).items():
            sig = export.signature
            line_match = re.search(r"#L(\d+)$", export.source)
            if line_match:
                line_idx = int(line_match.group(1)) - 1
                prev = "\n".join(lines[max(0, line_idx - 4) : line_idx])
                if "#[uniffi::constructor" in prev:
                    sig = f"#[uniffi::constructor] {sig}"
            callables[key] = {"signature": sig, "source": export.source}
        types.update(extract_uniffi_types_in(content, rel_src))
    return callables, types


def extract_c_surface(root: Path, sha: str) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Return `(functions, types)` exported by `crates/marmot-c/include/marmot.h` at `sha`."""
    header = _read_file_at(root, sha, "crates/marmot-c/include/marmot.h")
    if header is None:
        return {}, {}
    functions = {
        key: {"signature": export.signature, "source": export.source}
        for key, export in check_binding_docs.c_exports_in(header).items()
    }
    types = extract_c_types_in(header)
    return functions, types


def diff_callables(
    base: dict[str, dict[str, str]], target: dict[str, dict[str, str]]
) -> dict[str, list[dict[str, Any]]]:
    added = [
        {"name": key, "signature": target[key]["signature"], "source": target[key]["source"]}
        for key in sorted(target.keys() - base.keys())
    ]
    removed = [
        {"name": key, "signature": base[key]["signature"], "source": base[key]["source"]}
        for key in sorted(base.keys() - target.keys())
    ]
    changed = []
    for key in sorted(base.keys() & target.keys()):
        if base[key]["signature"] != target[key]["signature"]:
            changed.append({
                "name": key,
                "before": base[key]["signature"],
                "after": target[key]["signature"],
                "source": target[key]["source"],
            })
    return {"added": added, "removed": removed, "changed": changed}


def diff_types(base: dict[str, Any], target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    def _val(entry: Any) -> str:
        return entry["definition"] if isinstance(entry, dict) else str(entry)

    added = [{"name": key, "definition": _val(target[key])} for key in sorted(target.keys() - base.keys())]
    removed = [{"name": key, "definition": _val(base[key])} for key in sorted(base.keys() - target.keys())]
    changed = []
    for key in sorted(base.keys() & target.keys()):
        if _val(base[key]) != _val(target[key]):
            changed.append({"name": key, "before": _val(base[key]), "after": _val(target[key])})
    return {"added": added, "removed": removed, "changed": changed}


def detect_storage_migrations(root: Path, baseline_sha: str, target_sha: str) -> list[str]:
    """Return sorted storage migration files added or modified between baseline and target."""
    out = git_stdout(
        root,
        "diff",
        "--no-renames",
        "--name-only",
        "-z",
        "--diff-filter=AMCR",
        f"{baseline_sha}..{target_sha}",
    )
    return sorted(path for path in out.split("\0") if path and MIGRATION_FILE_RE.match(path))


def collect_commit_trailers(root: Path, baseline_sha: str, target_sha: str) -> list[dict[str, Any]]:
    """Inspect every first-parent commit in `baseline_sha..target_sha` for `Release-Impact:`."""
    revs = git_stdout(root, "rev-list", "--first-parent", "--reverse", f"{baseline_sha}..{target_sha}").splitlines()
    records: list[dict[str, Any]] = []
    for sha in revs:
        msg = git_stdout(root, "show", "-s", "--format=%B", sha)
        subject = msg.splitlines()[0].strip() if msg.splitlines() else ""
        trailers, errors = check_pr_trailers.extract_landed_trailers(msg)
        raw_impact = trailers.get("release-impact")
        impact = raw_impact.strip() if raw_impact and raw_impact.strip() in IMPACT_RANK else None
        records.append({
            "sha": sha,
            "short_sha": sha[:9],
            "subject": subject,
            "release_impact": impact,
            "trailer_errors": errors,
        })
    return records


def collect_changelog_fragments(root: Path, target_sha: str) -> dict[str, Any]:
    """Read all pending `changelog.d/` fragments present at `target_sha`."""
    tree = changelog.Tree(root, target_sha)
    grouped, group_errors = changelog.fragments_by_changelog(tree)
    by_section: dict[str, list[str]] = {}
    fragments: list[dict[str, Any]] = []
    parse_errors = list(group_errors)
    for cl_path, paths in sorted(grouped.items()):
        rel_cl = cl_path.relative_to(root).as_posix()
        for frag in sorted(paths):
            rel_frag = frag.relative_to(root).as_posix()
            sections, errs = changelog.parse_fragment(tree.read(frag))
            parse_errors.extend(f"{rel_frag}: {err}" for err in errs)
            fragments.append({
                "changelog": rel_cl,
                "path": rel_frag,
                "sections": list(sections.keys()),
                "entries": sections,
            })
            for sec, lines in sections.items():
                target_lines = by_section.setdefault(sec, [])
                if target_lines and lines and not (target_lines[0].startswith("- ") and lines[0].startswith("- ")):
                    target_lines.append("")
                target_lines.extend(lines)
    ordered_sections = {sec: by_section[sec] for sec in changelog.SECTIONS if sec in by_section}
    return {
        "fragment_count": len(fragments),
        "sections": ordered_sections,
        "fragments": fragments,
        "errors": parse_errors,
    }


def classify_range(
    root: Path,
    *,
    baseline_ref: str | None = None,
    target_ref: str = "HEAD",
    override_impact: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run all three classification layers and return `(impact_report, signature_delta)`."""
    target_sha = resolve_commit(root, target_ref)
    if baseline_ref:
        baseline_tag = baseline_ref
        tag_match = STABLE_TAG_RE.fullmatch(baseline_ref)
        baseline_version = (
            f"{tag_match.group(1)}.{tag_match.group(2)}.{tag_match.group(3)}"
            if tag_match
            else baseline_ref.lstrip("v")
        )
    else:
        baseline_tag, baseline_version = find_latest_stable_tag(root, target_sha)
    baseline_sha = resolve_commit(root, baseline_tag)
    # When `baseline_tag` points to a promoted `release/vX.Y.Z` branch commit,
    # its merge-base with `target_sha` is the RC `source_sha` on `master`.
    merge_base_probe = _git(root, "merge-base", baseline_sha, target_sha, check=False)
    history_base_sha = (
        merge_base_probe.stdout.strip()
        if merge_base_probe.returncode == 0 and merge_base_probe.stdout.strip()
        else baseline_sha
    )

    # Layer 1: Mechanical UniFFI & C ABI surface diff
    base_uniffi_fns, base_uniffi_types = extract_uniffi_surface(root, baseline_sha)
    target_uniffi_fns, target_uniffi_types = extract_uniffi_surface(root, target_sha)
    uniffi_fn_diff = diff_callables(base_uniffi_fns, target_uniffi_fns)
    uniffi_type_diff = diff_types(base_uniffi_types, target_uniffi_types)

    base_c_fns, base_c_types = extract_c_surface(root, baseline_sha)
    target_c_fns, target_c_types = extract_c_surface(root, target_sha)
    c_fn_diff = diff_callables(base_c_fns, target_c_fns)
    c_type_diff = diff_types(base_c_types, target_c_types)

    uniffi_breaking = (
        [f"removed UniFFI export `{item['name']}`" for item in uniffi_fn_diff["removed"]]
        + [f"changed UniFFI signature `{item['name']}`" for item in uniffi_fn_diff["changed"]]
        + [f"removed UniFFI type `{item['name']}`" for item in uniffi_type_diff["removed"]]
        + [f"changed UniFFI type `{item['name']}`" for item in uniffi_type_diff["changed"]]
    )
    c_breaking = (
        [f"removed C export `{item['name']}`" for item in c_fn_diff["removed"]]
        + [f"changed C signature `{item['name']}`" for item in c_fn_diff["changed"]]
        + [f"removed C type `{item['name']}`" for item in c_type_diff["removed"]]
        + [f"changed C type `{item['name']}`" for item in c_type_diff["changed"]]
    )
    uniffi_additive = (
        [f"added UniFFI export `{item['name']}`" for item in uniffi_fn_diff["added"]]
        + [f"added UniFFI type `{item['name']}`" for item in uniffi_type_diff["added"]]
    )
    c_additive = (
        [f"added C export `{item['name']}`" for item in c_fn_diff["added"]]
        + [f"added C type `{item['name']}`" for item in c_type_diff["added"]]
    )

    abi_impact = "none"
    if uniffi_breaking or c_breaking:
        abi_impact = "minor"
    elif uniffi_additive or c_additive:
        abi_impact = "patch"

    # Layer 2: Storage migrations & non-doc code paths
    migrations = detect_storage_migrations(root, history_base_sha, target_sha)
    changed_paths = [
        p
        for p in git_stdout(
            root, "diff", "--no-renames", "--name-only", "-z", f"{history_base_sha}..{target_sha}"
        ).split("\0")
        if p
    ]
    code_changed = any(
        p.startswith(("crates/", "integrations/")) and not p.endswith(".md")
        for p in changed_paths
    )
    storage_impact = "minor" if migrations else ("patch" if code_changed else "none")

    # Layer 3: Commit trailers & changelog.d fragments
    commits = collect_commit_trailers(root, history_base_sha, target_sha)
    minor_commits = [c for c in commits if c["release_impact"] == "minor"]
    patch_commits = [c for c in commits if c["release_impact"] == "patch"]
    trailer_impact = "minor" if minor_commits else ("patch" if patch_commits else "none")

    cl_data = collect_changelog_fragments(root, target_sha)
    if "Breaking changes" in cl_data["sections"]:
        changelog_impact = "minor"
    elif cl_data["sections"]:
        changelog_impact = "patch"
    else:
        changelog_impact = "none"

    triggers: list[str] = []
    if uniffi_breaking:
        triggers.append(f"UniFFI breaking ABI changes ({len(uniffi_breaking)}): " + ", ".join(uniffi_breaking[:5]))
    if c_breaking:
        triggers.append(f"C ABI breaking changes ({len(c_breaking)}): " + ", ".join(c_breaking[:5]))
    if migrations:
        triggers.append(
            f"SQLite storage migrations ({len(migrations)}): "
            + ", ".join(Path(m).name for m in migrations[:5])
        )
    if "Breaking changes" in cl_data["sections"]:
        triggers.append("Pending changelog.d fragment contains `### Breaking changes`")
    if minor_commits:
        triggers.append(
            f"Commit trailer `Release-Impact: minor` ({len(minor_commits)}): "
            + ", ".join(f"{c['short_sha']} ({c['subject']})" for c in minor_commits[:3])
        )
    if not triggers:
        if uniffi_additive or c_additive:
            triggers.append(
                f"Additive binding exports (UniFFI: +{len(uniffi_additive)}, C: +{len(c_additive)})"
            )
        if cl_data["sections"]:
            triggers.append(f"Pending changelog.d fragments ({cl_data['fragment_count']})")
        if patch_commits:
            triggers.append(f"Commit trailer `Release-Impact: patch` ({len(patch_commits)})")
        if code_changed and not triggers:
            triggers.append("Non-breaking code changes under crates/ or integrations/")

    computed_impact = _max_impact(abi_impact, storage_impact, trailer_impact, changelog_impact)
    effective_impact = override_impact if override_impact in IMPACT_RANK else computed_impact
    if override_impact and override_impact != computed_impact:
        triggers.insert(0, f"Human override applied: `{computed_impact}` -> `{override_impact}`")

    target_base = next_base_version(baseline_version, effective_impact)

    signature_delta = {
        "schema": 1,
        "baseline_tag": baseline_tag,
        "baseline_version": baseline_version,
        "baseline_sha": baseline_sha,
        "target_sha": target_sha,
        "target_base_version": target_base,
        "impact": effective_impact,
        "uniffi": {
            "breaking": uniffi_breaking,
            "functions": uniffi_fn_diff,
            "types": uniffi_type_diff,
        },
        "c_abi": {
            "breaking": c_breaking,
            "functions": c_fn_diff,
            "types": c_type_diff,
        },
        "storage_migrations": migrations,
    }

    impact_report = {
        "schema": 1,
        "baseline_tag": baseline_tag,
        "baseline_version": baseline_version,
        "baseline_sha": baseline_sha,
        "target_sha": target_sha,
        "computed_impact": computed_impact,
        "impact": effective_impact,
        "target_base_version": target_base,
        "triggers": triggers,
        "layers": {
            "mechanical_abi": {
                "impact": abi_impact,
                "uniffi_breaking_count": len(uniffi_breaking),
                "uniffi_additive_count": len(uniffi_additive),
                "c_breaking_count": len(c_breaking),
                "c_additive_count": len(c_additive),
            },
            "storage_migrations": {
                "impact": storage_impact,
                "migrations": migrations,
                "code_changed": code_changed,
            },
            "commit_trailers": {
                "impact": trailer_impact,
                "total_commits": len(commits),
                "minor_count": len(minor_commits),
                "patch_count": len(patch_commits),
                "missing_count": sum(1 for c in commits if c["release_impact"] is None),
            },
            "changelog_fragments": {
                "impact": changelog_impact,
                "fragment_count": cl_data["fragment_count"],
                "sections": list(cl_data["sections"].keys()),
            },
        },
        "changelog": cl_data["sections"],
        "commits": [
            {"sha": c["short_sha"], "subject": c["subject"], "release_impact": c["release_impact"]}
            for c in commits
        ],
    }

    return impact_report, signature_delta


def render_signature_delta_markdown(delta: dict[str, Any]) -> str:
    """Render a concise Markdown summary of UniFFI and C ABI changes for client agents."""
    lines = [
        f"# Binding Signature Delta (`{delta['baseline_tag']}` -> `{delta['target_sha'][:9]}`)",
        "",
        f"- **Baseline:** `{delta['baseline_tag']}` (`{delta['baseline_sha']}`)",
        f"- **Target:** `{delta['target_sha']}` (classified `{delta['impact']}`, target `{delta['target_base_version']}`)",
        "",
    ]

    def _emit_surface(title: str, surface: dict[str, Any]) -> None:
        fns = surface["functions"]
        types = surface["types"]
        lines.append(f"## {title}")
        lines.append("")
        if not any((fns["added"], fns["removed"], fns["changed"], types["added"], types["removed"], types["changed"])):
            lines.append("No exported signature or type changes.")
            lines.append("")
            return
        if fns["removed"]:
            lines.append("### Removed functions (breaking)")
            lines.append("")
            for item in fns["removed"]:
                lines.append(f"- `{item['name']}`: `{item['signature']}`")
            lines.append("")
        if fns["changed"]:
            lines.append("### Changed function signatures (breaking)")
            lines.append("")
            for item in fns["changed"]:
                lines.append(f"- `{item['name']}`")
                lines.append(f"  - before: `{item['before']}`")
                lines.append(f"  - after:  `{item['after']}`")
            lines.append("")
        if types["removed"] or types["changed"]:
            lines.append("### Removed or changed exported types (breaking)")
            lines.append("")
            for item in types["removed"]:
                lines.append(f"- Removed `{item['name']}`")
            for item in types["changed"]:
                lines.append(f"- Changed `{item['name']}`")
            lines.append("")
        if fns["added"]:
            lines.append("### Added functions")
            lines.append("")
            for item in fns["added"]:
                lines.append(f"- `{item['name']}`: `{item['signature']}`")
            lines.append("")
        if types["added"]:
            lines.append("### Added exported types")
            lines.append("")
            for item in types["added"]:
                lines.append(f"- `{item['name']}`")
            lines.append("")

    _emit_surface("UniFFI (`marmot-uniffi`)", delta["uniffi"])
    _emit_surface("C ABI (`marmot-c`)", delta["c_abi"])

    if delta["storage_migrations"]:
        lines.append("## SQLite Storage Migrations")
        lines.append("")
        lines.append(
            "Downgrade across these migrations is unsupported. Upgrade all processes sharing an "
            "account database together and keep a pre-upgrade backup/export."
        )
        lines.append("")
        for path in delta["storage_migrations"]:
            lines.append(f"- `{path}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_integration_notes(
    report: dict[str, Any],
    delta: dict[str, Any],
    *,
    version_label: str | None = None,
    release_notes_link: str | None = None,
    previous_guide_link: str | None = None,
) -> str:
    """Render rolling or finalized integration notes from the 3-layer classification."""
    version = version_label or report["target_base_version"]
    baseline_v = report["baseline_version"]
    lines = [
        f"# MDK {baseline_v} → {version} Integration Guide",
        "",
        "## Scope and provenance",
        "",
        f"- **Baseline:** `{report['baseline_tag']}` (`{report['baseline_sha']}`)",
        f"- **Target:** `{version}` (`{report['target_sha']}`)",
        f"- **Classified SemVer impact:** `{report['impact']}`",
    ]
    if release_notes_link:
        lines.append(f"- **Release notes:** [{version} release notes]({release_notes_link})")
    if previous_guide_link:
        lines.append(f"- **Previous guide:** [{baseline_v} integration guide]({previous_guide_link})")
    lines.append("")

    lines.append("## Impact triggers")
    lines.append("")
    if report["triggers"]:
        for trigger in report["triggers"]:
            lines.append(f"- {trigger}")
    else:
        lines.append("- No breaking ABI, migration, or changelog triggers detected.")
    lines.append("")

    if delta["storage_migrations"]:
        lines.extend([
            "## Storage migrations (required upgrade coordination)",
            "",
            "This release advances the SQLite account schema. Downgrade across these migrations is "
            "unsupported; update all processes opening the account database together:",
            "",
            *(f"- `{path}`" for path in delta["storage_migrations"]),
            "",
        ])

    lines.append("## Summary of changes")
    lines.append("")
    if report["changelog"]:
        for sec, sec_lines in report["changelog"].items():
            lines.append(f"### {sec}")
            lines.append("")
            lines.extend(sec_lines)
            lines.append("")
    else:
        lines.append("No pending `changelog.d/` entries recorded in this range.")
        lines.append("")

    lines.append("## Binding surface delta")
    lines.append("")
    lines.append(render_signature_delta_markdown(delta).split("\n", 1)[1].lstrip("\n").rstrip("\n"))
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_release_notes(
    report: dict[str, Any],
    delta: dict[str, Any],
    *,
    version: str,
    integration_guide_link: str,
) -> str:
    """Render concise `docs/release/<version>.md` notes with reciprocal integration link."""
    baseline_v = report["baseline_version"]
    lines = [
        f"# MDK {version}",
        "",
        f"Promoted from verified MDK commit `{report['target_sha']}` "
        f"(impact: `{report['impact']}` relative to `{report['baseline_tag']}`). "
        f"See the [{baseline_v} → {version} integration guide]({integration_guide_link}).",
        "",
    ]
    if delta["storage_migrations"]:
        lines.append(
            f"- **Storage migrations.** Adds/updates {len(delta['storage_migrations'])} SQLite "
            f"migration file(s); downgrade across schema migrations is unsupported. Roll out "
            "matching bindings and binaries to apps and extensions together."
        )
    if report["changelog"]:
        for sec, sec_lines in report["changelog"].items():
            lines.extend(["", f"## {sec}", "", *sec_lines])
    else:
        lines.append(f"- Includes {report['layers']['commit_trailers']['total_commits']} verified commit(s) since `{report['baseline_tag']}`.")

    lines.extend([
        "",
        "## Release artifacts",
        "",
        "| Track | Version to pin |",
        "| --- | --- |",
        f"| Rust workspace source | `v{version}` |",
        f"| WN Agent, gateway plugins, terminal harnesses and verified installers | `wn-agent-v{version}` |",
        f"| MarmotKit for iOS, macOS and Android | `marmotkit-v{version}` |",
        f"| Marmot C library and header | `marmotc-v{version}` |",
        "",
        "Verify the matching manifest and SHA-256 for each download and the SwiftPM checksum for Apple binary targets.",
        "Apple wrappers also need their matching Swift source and privacy resource. See the",
        "[MarmotKit distribution guide](../../crates/marmot-uniffi/DISTRIBUTION.md).",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--baseline-ref", help="stable baseline tag or commit (default: latest reachable vX.Y.Z tag)")
    parser.add_argument("--target-ref", default="HEAD", help="target commit or ref (default: HEAD)")
    parser.add_argument("--override-impact", choices=("patch", "minor"), help="explicitly override patch/minor impact")
    parser.add_argument("--impact-out", type=Path, help="write impact_report.json to this path")
    parser.add_argument("--delta-json-out", type=Path, help="write signature_delta.json to this path")
    parser.add_argument("--delta-md-out", type=Path, help="write signature_delta.md to this path")
    parser.add_argument("--notes-out", type=Path, help="write rolling integration notes Markdown to this path")
    args = parser.parse_args(argv)

    try:
        report, delta = classify_range(
            args.root,
            baseline_ref=args.baseline_ref,
            target_ref=args.target_ref,
            override_impact=args.override_impact,
        )
    except (ClassificationError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.impact_out:
        args.impact_out.parent.mkdir(parents=True, exist_ok=True)
        args.impact_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.delta_json_out:
        args.delta_json_out.parent.mkdir(parents=True, exist_ok=True)
        args.delta_json_out.write_text(json.dumps(delta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.delta_md_out:
        args.delta_md_out.parent.mkdir(parents=True, exist_ok=True)
        args.delta_md_out.write_text(render_signature_delta_markdown(delta), encoding="utf-8")
    if args.notes_out:
        args.notes_out.parent.mkdir(parents=True, exist_ok=True)
        args.notes_out.write_text(render_integration_notes(report, delta), encoding="utf-8")

    print(
        f"impact={report['impact']} base={report['target_base_version']} "
        f"baseline={report['baseline_tag']} target={report['target_sha'][:9]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
