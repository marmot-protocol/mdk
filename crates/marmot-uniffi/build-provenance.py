#!/usr/bin/env python3
"""Carry observed compiler identity from build jobs to release assemblers."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


PARTS = {
    "ios": {"swift", "ios-device", "ios-simulator"},
    "macos": {"swift", "macos"},
    "android": {"kotlin", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"},
}
NDK_FIELDS = ("android_ndk_home", "android_ndk_version", "android_api")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_set():
    def enabled(name):
        return os.environ.get(name, "0").lower() in {"1", "true"}

    return {
        "otlp_export": enabled("OTLP_EXPORT"),
        "product_analytics_export": enabled("PRODUCT_ANALYTICS_EXPORT"),
    }


def record(part, destination):
    workspace = os.environ["MARMOTKIT_WORKSPACE_DIR"]
    env = dict(os.environ, PATH=f"{Path.home()}/.cargo/bin:{os.environ['PATH']}")

    def command(*args):
        return subprocess.check_output(args, cwd=workspace, env=env, text=True).strip()

    profile = Path(__file__).with_name("marmotkit-release-profile.env")
    data = dict(part=part, source_sha=command("git", "rev-parse", "HEAD"),
                builder_sha=os.environ["BUILDER_SHA"],
                workflow_run_id=os.environ.get("GITHUB_RUN_ID", "local"),
                release_profile_sha256=sha256(profile), feature_set=feature_set(),
                rustc=command("rustc", "--version"), cargo=command("cargo", "--version"))
    if part in PARTS["android"] - {"kotlin"}:
        ndk = Path(os.environ["ANDROID_NDK_HOME"])
        properties = dict(line.split("=", 1) for line in
                          (ndk / "source.properties").read_text().splitlines() if "=" in line)
        properties = {key.strip(): value.strip() for key, value in properties.items()}
        data.update(android_ndk_home=str(ndk), android_ndk_version=properties["Pkg.Revision"],
                    android_api=os.environ.get("ANDROID_API", "26"),
                    library_sha256=android_library_sha256(part))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(data, indent=2) + "\n")


def android_library_sha256(part):
    workspace = Path(os.environ["MARMOTKIT_WORKSPACE_DIR"])
    crate = Path(os.environ.get("MARMOTKIT_CRATE_DIR", workspace / "crates/marmot-uniffi"))
    library = crate / "output/android/jniLibs" / part / "libmarmot_uniffi.so"
    if library.is_symlink() or not library.is_file():
        raise ValueError(f"{part}: missing Android library")
    return sha256(library)


def verify_android_libraries(records, root):
    if not root.is_dir():
        raise ValueError("android artifact root is missing")
    for record in records:
        part = record["part"]
        if part == "kotlin":
            if "library_sha256" in record:
                raise ValueError("kotlin input must not carry library_sha256")
            continue
        digest = record["library_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"{part}: invalid library_sha256")
        library = root / "jniLibs" / part / "libmarmot_uniffi.so"
        if library.is_symlink() or not library.is_file():
            raise ValueError(f"{part}: missing Android library")
        if sha256(library) != digest:
            raise ValueError(f"{part}: library checksum mismatch")


def verify(platform, paths, artifact_root=None):
    records = [json.loads(path.read_text()) for path in paths]
    if len(records) != len(PARTS[platform]) or {r["part"] for r in records} != PARTS[platform]:
        raise ValueError(f"expected exactly these build inputs: {sorted(PARTS[platform])}")
    expected = {
        "source_sha": os.environ["SOURCE_SHA"],
        "builder_sha": os.environ["BUILDER_SHA"],
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "release_profile_sha256": sha256(Path(__file__).with_name("marmotkit-release-profile.env")),
        "feature_set": feature_set(),
    }
    for record in records:
        for key, value in expected.items():
            if record[key] != value:
                raise ValueError(f"{record['part']}: mismatched {key}")

    values = {}
    for key in ("rustc", "cargo", *(NDK_FIELDS if platform == "android" else ())):
        applicable = [r for r in records if key not in NDK_FIELDS or r["part"] != "kotlin"]
        observed = {r[key] for r in applicable}
        if len(observed) != 1:
            raise ValueError(f"build inputs disagree on {key}")
        value = observed.pop()
        if not isinstance(value, str) or not value or any(c in value for c in "\n\r\0"):
            raise ValueError(f"invalid {key}")
        values[key] = value
    if platform == "android":
        if artifact_root is None:
            raise ValueError("android verification requires --artifact-root")
        verify_android_libraries(records, Path(artifact_root))
    # Write only after every input agrees; assemblers must never sample their
    # own toolchains to describe artifacts compiled on other runners.
    with open(os.environ["GITHUB_ENV"], "a") as output:
        for key, value in values.items():
            output.write(f"MARMOTKIT_BUILD_{key.upper()}={value}\n")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "record":
            record(sys.argv[2], Path(sys.argv[3]))
        elif len(sys.argv) >= 4 and sys.argv[1] == "verify":
            platform = sys.argv[2]
            arguments = sys.argv[3:]
            artifact_root = None
            if platform == "android":
                if len(arguments) < 3 or arguments[0] != "--artifact-root":
                    raise ValueError(
                        "usage: build-provenance.py verify android --artifact-root ROOT FILE..."
                    )
                artifact_root = Path(arguments[1])
                arguments = arguments[2:]
            if not arguments:
                raise ValueError("usage: build-provenance.py record PART FILE | verify PLATFORM FILE...")
            verify(platform, [Path(path) for path in arguments], artifact_root)
        else:
            raise ValueError("usage: build-provenance.py record PART FILE | verify PLATFORM FILE...")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"error: {error}")
