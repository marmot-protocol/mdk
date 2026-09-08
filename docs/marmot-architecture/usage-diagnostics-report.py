#!/usr/bin/env python3
"""Summarize sanitized Aptabase JSONL. Never print payload properties outside the catalogue."""
import argparse
import collections
import json
from pathlib import Path
import uuid

CATALOGUE = json.loads(Path(__file__).with_name("product-event-catalogue.json").read_text())
EVENTS = {e["name"]: e for e in CATALOGUE["events"]}
DIMENSIONS = ("operation", "outcome", "unit", "duration_bucket", "partial", "action", "screen", "section", "failure_stage", "error_class", "activity", "media_kind", "source")

BOUNDS = {"0": (0, 0), "1": (1, 1), "2": (2, 2), "3_5": (3, 5),
          "6_10": (6, 10), "11_20": (11, 20), "21_50": (21, 50),
          "51_100": (51, 100), "101_250": (101, 250),
          "251_1000": (251, 1000), "1001_plus": (1001, None)}


def summarize(rows):
    sessions = set()
    onboarding = collections.Counter()
    totals = {}
    invalid_rows = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid_rows += 1
            continue
        name = row.get("eventName", row.get("event_name", ""))
        if not isinstance(name, str) or name not in EVENTS:
            invalid_rows += 1
            continue
        schema = EVENTS[name]
        props = row.get("props", row.get("string_props", row.get("stringProps", {})))
        if isinstance(props, str):
            try:
                props = json.loads(props)
            except (ValueError, TypeError):
                invalid_rows += 1
                continue
        if not isinstance(props, dict):
            invalid_rows += 1
            continue
        allowed = schema["properties"]
        if any(k in allowed and v not in allowed[k] for k, v in props.items()):
            invalid_rows += 1
            continue
        if name == "mdk_session_started":
            # Only ephemeral foreground-session identifiers enter this denominator.
            try:
                session = uuid.UUID(row.get("sessionId", row.get("session_id", "")))
                if session.version != 4:
                    raise ValueError()
                sessions.add(str(session))
            except (ValueError, TypeError, AttributeError):
                invalid_rows += 1
        elif name == "mdk_onboarding_step":
            step = props.get("step")
            if step in ("start", "identity_selection", "local_ready", "network_ready", "complete"):
                onboarding[step] += 1
        elif name.endswith("_summary") or name.startswith("app_"):
            bucket = props.get("count_bucket")
            if not isinstance(bucket, str) or bucket not in BOUNDS:
                continue
            dimensions = DIMENSIONS
            key = tuple([name] + [props.get(k, "") if k in allowed else "" for k in dimensions])
            low, high = BOUNDS[bucket]
            cell = totals.setdefault(key, [0, 0, 0])
            cell[0] += low
            cell[1] = None if high is None or cell[1] is None else cell[1] + high
            cell[2] += 1
    return {"observed_foreground_sessions": len(sessions),
            "observed_onboarding_steps": dict(onboarding),
            "measurements": [dict(zip(("event",) + DIMENSIONS, key),
                                  count_lower=values[0], count_upper=values[1], rows=values[2])
                             for key, values in sorted(totals.items())],
            "invalid_rows": invalid_rows,
            "notes": ["Counts are bucket bounds; a null upper bound is unbounded.",
                      "Backlog sums represent state samples, not unique obligations or failures.",
                      "Sessions are observed opted-in foreground sessions, not people.",
                      "Partial and complete windows are separate; lost data is not inferred."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", help="Sanitized Aptabase JSONL file")
    args = parser.parse_args()
    with open(args.export, encoding="utf-8") as source:
        print(json.dumps(summarize(json.loads(line) for line in source if line.strip()), indent=2))


if __name__ == "__main__":
    main()
