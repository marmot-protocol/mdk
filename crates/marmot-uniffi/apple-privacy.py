#!/usr/bin/env python3
"""Render the reviewed, feature-selected SDK privacy manifest."""

import argparse
from pathlib import Path
import plistlib

HERE = Path(__file__).resolve().parent
NAME = "marmot_uniffiFFI"


def privacy_manifest(analytics=False, privacy_dir=HERE / "apple-privacy"):
    with (privacy_dir / "PrivacyInfo.xcprivacy").open("rb") as f:
        manifest = plistlib.load(f)
    if analytics:
        with (privacy_dir / "product-analytics.plist").open("rb") as f:
            additions = plistlib.load(f)["NSPrivacyCollectedDataTypes"]
        rows = {r["NSPrivacyCollectedDataType"]: r for r in manifest["NSPrivacyCollectedDataTypes"]}
        for row in additions:
            key = row["NSPrivacyCollectedDataType"]
            if key in rows:
                rows[key]["NSPrivacyCollectedDataTypePurposes"] += row["NSPrivacyCollectedDataTypePurposes"]
            else:
                manifest["NSPrivacyCollectedDataTypes"].append(row)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--privacy-dir", type=Path, required=True)
    parser.add_argument("--product-analytics", choices=["0", "1", "true", "false"], required=True)
    args = parser.parse_args()
    args.output.write_bytes(plistlib.dumps(privacy_manifest(
        args.product_analytics in ("1", "true"), args.privacy_dir), sort_keys=False))
