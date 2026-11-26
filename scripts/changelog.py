#!/usr/bin/env python3
"""Keep unreleased changelog entries in fragment files.

Every CHANGELOG.md takes its unreleased entries from the `changelog.d/`
directory beside it, one Markdown file per change. Concurrent pull requests
each add a new file instead of editing the same lines, so they cannot
conflict. A release folds the fragments HEAD holds into CHANGELOG.md under the
version's heading and deletes them.

A fragment holds one or more `### <Section>` headings, each followed by its
entries:

    ### Fixed

    - Cancelling a Swift task now cancels the MarmotKit call it awaits.

Usage:

    changelog.py check [--none-pending [CHANGELOG.md ...]]
                                          validate fragments; with --none-pending also
                                          fail while a fragment is left (for the named
                                          changelogs, or any)
    changelog.py release <version> [CHANGELOG.md ...] [--date YYYY-MM-DD]
                                          fold the fragments into their CHANGELOG.md
                                          (the named ones, or every one)
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAGMENT_DIR = "changelog.d"
# Release order of the sections a fragment may use.
SECTIONS = ("Breaking changes", "Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
FRAGMENT_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*\.md$")
# The release version grammar of scripts/cut-full-release.sh.
VERSION = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
ATX_HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+(?P<text>.*)$")
SETEXT_UNDERLINE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
# What heading text renders as, without escapes, emphasis, code, link brackets or HTML tags.
MARKUP = re.compile(r"<[^>]*>|[\\*_`~\[\]]")
# The tag of each artifact track; any of them for a version means it shipped (release.md).
TRACK_TAG_PREFIXES = ("v", "wn-agent-v", "marmotkit-v", "marmotc-v")
# Keep a Changelog compare links, e.g. `[Unreleased]: https://.../compare/marmotc-v0.19.0...HEAD`.
UNRELEASED_LINK = re.compile(r"^\[Unreleased\]: (?P<compare>\S+/compare/)(?P<prefix>[A-Za-z-]*)(?P<previous>\S+)\.\.\.HEAD$")


def unreleased_headings(text: list[str]) -> list[int]:
    """Line numbers of the headings Markdown renders as starting with "Unreleased"."""
    found: list[int] = []
    paragraph: list[tuple[int, str]] = []  # the lines since the last blank line, which an underline makes a heading
    for number, line in enumerate(text, 1):
        if heading := ATX_HEADING.match(line):
            start, title = number, heading["text"]
        elif paragraph and SETEXT_UNDERLINE.match(line):
            start, title = paragraph[0][0], " ".join(part for _, part in paragraph)
        else:
            paragraph = paragraph + [(number, line)] if line.strip() else []
            continue
        paragraph = []
        if html.unescape(MARKUP.sub("", title)).strip().lower().startswith("unreleased"):
            found.append(start)
    return found


class Tree:
    """The repository's files as the working tree holds them (tracked and untracked, not ignored), or a commit."""

    def __init__(self, root: Path, commit: str | None = None) -> None:
        self.root, self.commit = root, commit
        if commit is None:
            names = self.git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
            self.files = sorted({root / name for name in names if name and (root / name).is_file()})
        else:
            names = self.git("ls-tree", "-r", "-z", "--name-only", commit).split("\0")
            self.files = sorted(root / name for name in names if name)

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True,
                              text=True, encoding="utf-8").stdout

    def read(self, path: Path) -> str:
        if self.commit is None:
            return path.read_text(encoding="utf-8")
        return self.git("show", f"{self.commit}:{path.relative_to(self.root).as_posix()}")


def parse_fragment(content: str) -> tuple[dict[str, list[str]], list[str]]:
    """Return the fragment's entries by section, and its problems."""
    text = content.splitlines()
    sections, errors = parse_sections(text)
    # Folded in, it would fail the changelog's own check, even inside a code block.
    return sections, errors + [f"line {number}: a heading that renders as Unreleased"
                               for number in unreleased_headings(text)]


def parse_sections(text: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    sections: dict[str, list[str]] = {}
    errors: list[str] = []
    current: str | None = None
    for number, line in enumerate(text, 1):
        if line.startswith("### "):
            current = line[4:].strip()
            if current not in SECTIONS:
                errors.append(f"line {number}: unknown section {current!r}; use one of: {', '.join(SECTIONS)}")
            sections.setdefault(current, [])
        elif re.match(r"^#{1,2}\s", line):
            errors.append(f"line {number}: only `### <Section>` headings belong in a fragment")
        elif current is None:
            if line.strip():
                errors.append(f"line {number}: text before the first `### <Section>` heading")
        else:
            sections[current].append(line)
    for name, lines in sections.items():
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if not lines:
            errors.append(f"section {name!r} has no entries")
    if not sections and not errors:
        errors.append("no `### <Section>` heading")
    return sections, errors


def fragments_by_changelog(tree: Tree) -> tuple[dict[Path, list[Path]], list[str]]:
    """Group fragment files under the CHANGELOG.md beside their directory."""
    grouped: dict[Path, list[Path]] = {}
    errors: list[str] = []
    files = set(tree.files)
    for path in tree.files:
        rel = path.relative_to(tree.root)
        if FRAGMENT_DIR not in rel.parts[:-1]:
            continue
        changelog = path.parent.parent / "CHANGELOG.md"
        if path.parent.name != FRAGMENT_DIR:
            errors.append(f"{rel}: fragments go directly in {FRAGMENT_DIR}/, not a subdirectory")
        elif changelog not in files:
            errors.append(f"{rel}: no CHANGELOG.md beside {rel.parent}")
        elif not FRAGMENT_NAME.match(path.name):
            errors.append(f"{rel}: name a fragment <lowercase-kebab-slug>.md")
        else:
            grouped.setdefault(changelog, []).append(path)
    return grouped, errors


def check(tree: Tree, none_pending: bool, only: list[Path] | None = None) -> list[str]:
    root = tree.root
    grouped, errors = fragments_by_changelog(tree)
    for changelog in (path for path in tree.files if path.name == "CHANGELOG.md"):
        for number in unreleased_headings(tree.read(changelog).splitlines()):
            rel = changelog.relative_to(root)
            errors.append(
                f"{rel}:{number}: no Unreleased section; add each entry as a fragment in "
                f"{rel.parent / FRAGMENT_DIR}/ instead"
            )
    for paths in grouped.values():
        for path in paths:
            errors += [f"{path.relative_to(root)}: {e}" for e in parse_fragment(tree.read(path))[1]]
    if none_pending:
        # The fold takes only what HEAD holds.
        committed = set(Tree(root, "HEAD").files)
        errors += [f"{p.relative_to(root)}: still pending; "
                   + ("run `just changelog-release <version>`" if p in committed else "commit or remove it")
                   for changelog, paths in grouped.items() if only is None or changelog in only for p in paths]
    return errors


def release_section(heading: str, parts: list[dict[str, list[str]]]) -> list[str]:
    merged: dict[str, list[str]] = {}
    for sections in parts:
        for name, lines in sections.items():
            entries = merged.setdefault(name, [])
            # Bullets from separate fragments join one list; anything else
            # keeps a blank line, or two paragraphs would render as one.
            if entries and not (entries[0].startswith("- ") and lines[0].startswith("- ")):
                entries.append("")
            entries.extend(lines)
    out = [heading, ""]
    for name in SECTIONS:
        if name in merged:
            out += [f"### {name}", "", *merged[name], ""]
    return out


def shipped_tags(root: Path, version: str) -> tuple[list[str], list[str]]:
    """The version's track tags, here or on origin, where a tag this checkout lacks may already be."""
    tags = [f"{prefix}{version}" for prefix in TRACK_TAG_PREFIXES]
    git = ["git", "-C", str(root)]
    local = subprocess.run([*git, "tag", "--list", *tags], check=True, capture_output=True, text=True)
    remote = subprocess.run([*git, "ls-remote", "--tags", "origin", *(f"refs/tags/{tag}" for tag in tags)],
                            capture_output=True, text=True)
    if remote.returncode != 0:
        return [], [f"cannot read origin's release tags, so cannot tell whether {version} shipped: "
                    f"{remote.stderr.strip()}"]
    on_origin = {line.split("refs/tags/", 1)[1].removesuffix("^{}") for line in remote.stdout.splitlines()}
    return sorted(set(local.stdout.split()) | on_origin), []


def replace_text(path: Path, text: str) -> None:
    """Write through a sibling file, so an interrupted write leaves the old content whole."""
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False)
    try:
        with tmp:
            tmp.write(text)
        shutil.copymode(path, tmp.name)
        os.replace(tmp.name, path)
    except BaseException:
        os.unlink(tmp.name)
        raise


def release(root: Path, version: str, date: str, only: list[Path] | None = None) -> list[str]:
    # Fold what HEAD holds, so a re-run after an interruption computes the same files.
    head = Tree(root, "HEAD")
    errors = check(head, none_pending=False)
    if errors:
        return errors
    # A shipped version's notes describe its tagged tree: later fragments belong to the next.
    tagged, errors = shipped_tags(root, version)
    if errors:
        return errors
    if tagged:
        return [f"{version} is tagged ({', '.join(tagged)}); fold these fragments into the next release"]
    grouped, _ = fragments_by_changelog(head)
    grouped = {changelog: paths for changelog, paths in grouped.items() if only is None or changelog in only}
    released = re.compile(rf"^## \[?{re.escape(version)}\]?(\s|$)")
    folded: dict[Path, str] = {}
    for changelog, fragments in sorted(grouped.items()):
        rel = changelog.relative_to(root)
        committed = head.read(changelog)
        lines = committed.splitlines()
        parts = [parse_fragment(head.read(path))[0] for path in fragments]
        headings = [i for i, line in enumerate(lines) if line.startswith("## ")] + [len(lines)] * 2
        at, end = headings[0], headings[1]
        if at < len(lines) and released.match(lines[at]):
            # A fragment that merged after the release PR joins that version until it is tagged.
            existing, problems = parse_sections(lines[at + 1:end])
            if problems:
                errors += [f"{rel} {version} section: {problem}" for problem in problems]
            else:
                lines[at:end] = release_section(lines[at], [existing, *parts])
        elif any(released.match(line) for line in lines):
            errors.append(f"{rel}: {version} is not the newest version heading")
        else:
            bracketed = any(line.startswith("## [") for line in lines)
            heading = f"## [{version}] - {date}" if bracketed else f"## {version} - {date}"
            lines[at:at] = release_section(heading, parts)
            for i, line in enumerate(lines):
                if link := UNRELEASED_LINK.match(line):
                    compare, prefix = link["compare"], link["prefix"]
                    lines[i:i + 1] = [
                        f"[Unreleased]: {compare}{prefix}{version}...HEAD",
                        f"[{version}]: {compare}{prefix}{link['previous']}...{prefix}{version}",
                    ]
                    break
        folded[changelog] = "\n".join(lines) + "\n"
        # Local edits would be lost; an interrupted fold left either HEAD's text or this fold's.
        if not changelog.is_file() or changelog.read_text(encoding="utf-8") not in (committed, folded[changelog]):
            errors.append(f"{rel}: differs from HEAD and from this fold; commit or restore it first "
                          f"(an interrupted fold re-runs with its first --date)")
        errors += [f"{path.relative_to(root)}: differs from HEAD; commit or restore it first" for path in fragments
                   if path.is_file() and path.read_text(encoding="utf-8") != head.read(path)]
    if errors:
        return errors
    # Every changelog is whole before any fragment goes; a re-run finishes an interrupted fold.
    for changelog, text in folded.items():
        replace_text(changelog, text)
    for changelog in folded:
        for path in grouped[changelog]:
            path.unlink(missing_ok=True)
        print(f"{changelog.relative_to(root)}: {version} from {len(grouped[changelog])} fragment(s)")
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check_cmd = sub.add_parser("check", help="validate fragments and changelogs")
    check_cmd.add_argument("--none-pending", action="store_true", help="also fail while a fragment is left")
    check_cmd.add_argument("changelogs", nargs="*", type=Path, help="limit --none-pending to these")
    release_cmd = sub.add_parser("release", help="fold the fragments into their CHANGELOG.md")
    release_cmd.add_argument("version")
    release_cmd.add_argument("changelogs", nargs="*", type=Path, help="fold only these")
    release_cmd.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    args = parser.parse_args()
    only = [(Path.cwd() / path).resolve() for path in args.changelogs] or None
    changelogs = {path.resolve() for path in Tree(ROOT).files if path.name == "CHANGELOG.md"}
    unknown = [str(path) for path in only or [] if path not in changelogs]

    if unknown:
        errors = [f"not a CHANGELOG.md in this repository: {path}" for path in unknown]
    elif args.command == "check":
        errors = check(Tree(ROOT), args.none_pending, only)
    elif not VERSION.match(args.version):
        errors = [f"{args.version!r} is not a version like 0.20.0 or 0.20.0-rc-1"]
    elif not re.match(r"^\d{4}-\d{2}-\d{2}$", args.date):
        errors = [f"{args.date!r} is not a YYYY-MM-DD date"]
    else:
        errors = release(ROOT, args.version, args.date, only)
    for error in errors:
        print(f"changelog: {error}", file=sys.stderr)
    if errors:
        return 1
    if args.command == "check":
        print("changelog: fragments ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
