#!/usr/bin/env python3
"""Patch Hermes gateway config for the Marmot phone-test profile."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError as exc:  # pragma: no cover - exercised on hosts without PyYAML.
    if exc.name != "yaml":
        raise
    yaml = None


VALID_TOOL_PROGRESS = {"off", "new", "all", "verbose"}
VALID_STREAMING_TRANSPORT = {"auto", "draft", "edit", "off"}


def parse_bool(value: str, *, name: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean-ish value, got {value!r}")


def _parse_scalar(value: str) -> Any:
    normalized = value.strip()
    lowered = normalized.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {"'", '"'}
    ):
        return normalized[1:-1]
    if re.fullmatch(r"-?[0-9]+", normalized):
        try:
            return int(normalized)
        except ValueError:
            pass
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", normalized):
        try:
            return float(normalized)
        except ValueError:
            pass
    return normalized


def _simple_yaml_load(text: str) -> dict[str, Any]:
    """Load the small mapping subset we emit when PyYAML is unavailable."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            raise ValueError(f"unsupported tab indentation on line {line_number}")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if ":" not in stripped:
            raise ValueError(f"unsupported YAML line {line_number}: {raw_line!r}")
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"missing YAML key on line {line_number}")

        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError(f"invalid YAML indentation on line {line_number}")
        parent = stack[-1][1]
        if not value:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_scalar(value)

    return root


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text and re.fullmatch(r"[A-Za-z0-9_./:@,+-]+", text):
        return text
    return "'" + text.replace("'", "''") + "'"


def _simple_yaml_dump(data: dict[str, Any]) -> str:
    lines: list[str] = []

    def emit_mapping(mapping: dict[str, Any], indent: int) -> None:
        prefix = " " * indent
        for key, value in mapping.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                emit_mapping(value, indent + 2)
            else:
                lines.append(f"{prefix}{key}: {_format_scalar(value)}")

    emit_mapping(data, 0)
    return "\n".join(lines) + "\n"


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        loaded = yaml.safe_load(text) or {}
    else:
        loaded = _simple_yaml_load(text)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return loaded


def dump_config(config: dict[str, Any]) -> str:
    if yaml is not None:
        return yaml.safe_dump(config, sort_keys=False, default_flow_style=False)
    return _simple_yaml_dump(config)


def _ensure_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    current = parent.get(key)
    if isinstance(current, dict):
        return current
    replacement: dict[str, Any] = {}
    parent[key] = replacement
    return replacement


def configure_gateway_config(
    *,
    hermes_home: Path,
    platform: str,
    streaming_enabled: bool,
    streaming_transport: str,
    tool_progress: str,
    interim_assistant_messages: bool,
    long_running_notifications: bool,
    busy_ack_detail: bool,
) -> Path:
    if streaming_transport not in VALID_STREAMING_TRANSPORT:
        valid = ", ".join(sorted(VALID_STREAMING_TRANSPORT))
        raise ValueError(f"streaming transport must be one of: {valid}")
    if tool_progress not in VALID_TOOL_PROGRESS:
        valid = ", ".join(sorted(VALID_TOOL_PROGRESS))
        raise ValueError(f"tool progress must be one of: {valid}")

    config_path = hermes_home / "config.yaml"
    hermes_home.mkdir(parents=True, exist_ok=True)
    config = load_config(config_path)
    effective_streaming = streaming_enabled and streaming_transport != "off"

    streaming = _ensure_mapping(config, "streaming")
    streaming["enabled"] = streaming_enabled
    streaming["transport"] = streaming_transport

    display = _ensure_mapping(config, "display")
    platforms = _ensure_mapping(display, "platforms")
    platform_config = _ensure_mapping(platforms, platform)
    platform_config["streaming"] = effective_streaming
    platform_config["tool_progress"] = tool_progress
    platform_config["interim_assistant_messages"] = interim_assistant_messages
    platform_config["long_running_notifications"] = long_running_notifications
    platform_config["busy_ack_detail"] = busy_ack_detail

    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp_path.write_text(dump_config(config), encoding="utf-8")
    os.replace(tmp_path, config_path)
    return config_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", default=os.environ.get("HERMES_HOME", "~/.hermes"))
    parser.add_argument("--platform", default="marmot")
    parser.add_argument("--streaming", default=os.environ.get("HERMES_MARMOT_STREAMING", "1"))
    parser.add_argument(
        "--transport",
        default=os.environ.get("HERMES_MARMOT_STREAMING_TRANSPORT", "auto"),
        choices=sorted(VALID_STREAMING_TRANSPORT),
    )
    parser.add_argument(
        "--tool-progress",
        default=os.environ.get("HERMES_MARMOT_TOOL_PROGRESS", "off"),
        choices=sorted(VALID_TOOL_PROGRESS),
    )
    parser.add_argument(
        "--interim-messages",
        default=os.environ.get("HERMES_MARMOT_INTERIM_MESSAGES", "0"),
    )
    parser.add_argument(
        "--long-running-notifications",
        default=os.environ.get("HERMES_MARMOT_LONG_RUNNING_NOTIFICATIONS", "0"),
    )
    parser.add_argument(
        "--busy-ack-detail",
        default=os.environ.get("HERMES_MARMOT_BUSY_ACK_DETAIL", "0"),
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        streaming_enabled = parse_bool(args.streaming, name="streaming")
        interim_assistant_messages = parse_bool(
            args.interim_messages,
            name="interim messages",
        )
        long_running_notifications = parse_bool(
            args.long_running_notifications,
            name="long-running notifications",
        )
        busy_ack_detail = parse_bool(args.busy_ack_detail, name="busy ack detail")
        config_path = configure_gateway_config(
            hermes_home=Path(args.home).expanduser(),
            platform=args.platform,
            streaming_enabled=streaming_enabled,
            streaming_transport=args.transport,
            tool_progress=args.tool_progress,
            interim_assistant_messages=interim_assistant_messages,
            long_running_notifications=long_running_notifications,
            busy_ack_detail=busy_ack_detail,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(
            "Hermes Marmot gateway config:"
            f" path={config_path}"
            f" streaming={str(streaming_enabled).lower()}"
            f" transport={args.transport}"
            f" tool_progress={args.tool_progress}"
            f" interim_messages={str(interim_assistant_messages).lower()}"
            f" long_running_notifications={str(long_running_notifications).lower()}"
            f" busy_ack_detail={str(busy_ack_detail).lower()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
