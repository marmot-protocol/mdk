#!/usr/bin/env python3
"""Patch Hermes gateway config for the Marmot phone-test profile."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError as exc:  # pragma: no cover - exercised on hosts without PyYAML.
    if exc.name != "yaml":
        raise
    yaml = None


VALID_TOOL_PROGRESS = {"off", "new", "all", "verbose"}
VALID_STREAMING_TRANSPORT = {"auto", "draft", "edit", "off"}
MANAGED_ENV_KEYS = ("MARMOT_ALLOWED_USERS", "MARMOT_ALLOW_ALL_USERS")
ACCOUNT_ID_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_VALUES = {character: index for index, character in enumerate(_BECH32_CHARSET)}


@dataclass(frozen=True)
class HermesEnvAuthState:
    allowed_users_hex: list[str]
    allow_all_users: bool


def _bech32_polymod(values: Iterable[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _convert_bits(values: Iterable[int], from_bits: int, to_bits: int) -> Optional[bytes]:
    accumulator = 0
    bit_count = 0
    result = bytearray()
    max_value = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            return None
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & max_value)
    if bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & max_value):
        return None
    return bytes(result)


def _npub_to_hex(value: str) -> Optional[str]:
    if not value or len(value) > 90 or (value.lower() != value and value.upper() != value):
        return None
    normalized = value.lower()
    separator = normalized.rfind("1")
    if separator <= 0 or normalized[:separator] != "npub" or separator + 7 > len(normalized):
        return None
    try:
        data = [_BECH32_VALUES[character] for character in normalized[separator + 1 :]]
    except KeyError:
        return None
    hrp = normalized[:separator]
    expanded_hrp = [ord(character) >> 5 for character in hrp]
    expanded_hrp.extend([0])
    expanded_hrp.extend(ord(character) & 31 for character in hrp)
    if _bech32_polymod([*expanded_hrp, *data]) != 1:
        return None
    decoded = _convert_bits(data[:-6], 5, 8)
    if decoded is None or len(decoded) != 32:
        return None
    return decoded.hex()


def normalize_account_id(entry: str) -> str:
    normalized = str(entry).strip()
    if not normalized:
        return ""
    if normalized.lower().startswith("npub1"):
        return _npub_to_hex(normalized) or ""
    return normalized.lower().removeprefix("0x")


def _validate_account_id(entry: str, *, label: str) -> str:
    normalized = normalize_account_id(entry)
    if not ACCOUNT_ID_HEX_RE.fullmatch(normalized):
        raise ValueError(
            f"invalid {label}: expected a Nostr npub or 64-character hex account id"
        )
    return normalized


def validate_sender_auth_entries(entries: list[str]) -> None:
    for entry in entries:
        if not str(entry).strip():
            raise ValueError("invalid allowed user: empty value is not allowed")
        _validate_account_id(entry, label="allowed user")


def _parse_dotenv_scalar(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        if end == -1:
            return value[1:]
        return value[1:end]
    value = re.sub(r"\s+#.*$", "", value).strip()
    return value


def _parse_allowed_users_value(raw_value: str) -> list[str]:
    parsed = _parse_dotenv_scalar(raw_value)
    if not parsed.strip():
        return []
    users: list[str] = []
    for entry in parsed.split(","):
        normalized = normalize_account_id(entry)
        if not normalized:
            if entry.strip():
                raise ValueError("invalid MARMOT_ALLOWED_USERS entry")
            continue
        if not ACCOUNT_ID_HEX_RE.fullmatch(normalized):
            raise ValueError("invalid MARMOT_ALLOWED_USERS entry")
        users.append(normalized)
    return sorted(dict.fromkeys(users))


def _parse_allow_all_value(raw_value: str) -> bool:
    return parse_bool(_parse_dotenv_scalar(raw_value), name="MARMOT_ALLOW_ALL_USERS")


def _managed_env_key(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" not in stripped:
        return None
    key = stripped.split("=", 1)[0].strip()
    if key.startswith("export "):
        key = key[7:].strip()
    if key in MANAGED_ENV_KEYS:
        return key
    return None


def _managed_env_export_prefix(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("export "):
        return "export "
    return ""


def read_hermes_env_auth_from_lines(lines: list[str]) -> HermesEnvAuthState:
    allowed_users: list[str] | None = None
    allow_all_users: bool | None = None
    for line in lines:
        key = _managed_env_key(line)
        if key is None:
            continue
        _, raw_value = line.split("=", 1)
        if key == "MARMOT_ALLOWED_USERS":
            allowed_users = _parse_allowed_users_value(raw_value)
        elif key == "MARMOT_ALLOW_ALL_USERS":
            allow_all_users = _parse_allow_all_value(raw_value)

    if allowed_users is None:
        allowed_users = []
    if allow_all_users is None:
        allow_all_users = False
    return HermesEnvAuthState(
        allowed_users_hex=allowed_users,
        allow_all_users=allow_all_users,
    )


def read_hermes_env_auth(env_path: Path) -> HermesEnvAuthState:
    if not env_path.exists():
        return HermesEnvAuthState(allowed_users_hex=[], allow_all_users=False)
    return read_hermes_env_auth_from_lines(
        env_path.read_text(encoding="utf-8").splitlines()
    )


def _render_env_lines(
    *,
    existing_lines: list[str],
    allowed_users_hex: list[str],
    allow_all_users: bool,
) -> list[str]:
    rendered_allowed = f"MARMOT_ALLOWED_USERS={','.join(allowed_users_hex)}"
    rendered_allow_all = f"MARMOT_ALLOW_ALL_USERS={'true' if allow_all_users else 'false'}"
    managed_values = {
        "MARMOT_ALLOWED_USERS": rendered_allowed,
        "MARMOT_ALLOW_ALL_USERS": rendered_allow_all,
    }
    last_indices: dict[str, int] = {}
    managed_prefixes: dict[str, str] = {}
    for index, line in enumerate(existing_lines):
        key = _managed_env_key(line)
        if key is not None:
            last_indices[key] = index
            managed_prefixes[key] = _managed_env_export_prefix(line)

    output: list[str] = []
    seen: set[str] = set()
    for index, line in enumerate(existing_lines):
        key = _managed_env_key(line)
        if key is None:
            output.append(line)
            continue
        if last_indices.get(key) != index:
            continue
        output.append(f"{managed_prefixes.get(key, '')}{managed_values[key]}")
        seen.add(key)

    for key in MANAGED_ENV_KEYS:
        if key in seen:
            continue
        output.append(managed_values[key])
    return output


def _write_env_atomically(env_path: Path, lines: list[str]) -> None:
    env_path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if text and not text.endswith("\n"):
        text += "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=env_path.parent)
    tmp_path = Path(tmp_name)
    owns_fd = True
    try:
        try:
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            os.close(fd)
            owns_fd = False
            raise
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                owns_fd = False
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            if owns_fd:
                os.close(fd)
                owns_fd = False
            raise
        os.replace(tmp_path, env_path)
    except Exception:
        if owns_fd:
            os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise


def prepare_hermes_env(
    *,
    hermes_home: Path,
    add_allowed_users: list[str] | None = None,
    allow_all_opt_in: bool = False,
) -> tuple[HermesEnvAuthState, Path, list[str]]:
    env_path = hermes_home / ".env"
    existing_lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    current = read_hermes_env_auth_from_lines(existing_lines)

    normalized_new = [
        _validate_account_id(entry, label="allowed user")
        for entry in (add_allowed_users or [])
    ]
    merged_users = sorted(dict.fromkeys([*current.allowed_users_hex, *normalized_new]))
    merged_allow_all = current.allow_all_users or allow_all_opt_in

    if not merged_users and not merged_allow_all:
        raise ValueError(
            "Hermes Marmot authorization is not configured: add at least one "
            "--allow-user npub-or-hex, opt into --allow-all-users, or keep an "
            "existing valid allowlist in $HERMES_HOME/.env"
        )

    rendered_lines = _render_env_lines(
        existing_lines=existing_lines,
        allowed_users_hex=merged_users,
        allow_all_users=merged_allow_all,
    )
    return (
        HermesEnvAuthState(
            allowed_users_hex=merged_users,
            allow_all_users=merged_allow_all,
        ),
        env_path,
        rendered_lines,
    )


def configure_hermes_env(
    *,
    hermes_home: Path,
    add_allowed_users: list[str] | None = None,
    allow_all_opt_in: bool = False,
    dry_run: bool = False,
) -> HermesEnvAuthState:
    env_state, env_path, rendered_lines = prepare_hermes_env(
        hermes_home=hermes_home,
        add_allowed_users=add_allowed_users,
        allow_all_opt_in=allow_all_opt_in,
    )
    if not dry_run:
        _write_env_atomically(env_path, rendered_lines)
    return env_state


def _restore_path_bytes(
    path: Path,
    backup: bytes | None,
    backup_mode: int | None,
) -> None:
    if backup is None:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    restore_mode = backup_mode if backup_mode is not None else 0o600
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.rollback.",
        suffix=".tmp",
        dir=path.parent,
    )
    tmp_path = Path(tmp_name)
    owns_fd = True
    try:
        os.chmod(tmp_path, restore_mode)
        with os.fdopen(fd, "wb") as handle:
            owns_fd = False
            handle.write(backup)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if owns_fd:
            os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise


def _read_path_backup(path: Path | None) -> tuple[bytes | None, int | None]:
    if path is None:
        return None, None
    try:
        with path.open("rb") as handle:
            return handle.read(), stat.S_IMODE(os.fstat(handle.fileno()).st_mode)
    except FileNotFoundError:
        return None, None


def commit_env_and_config_transaction(
    *,
    env_path: Path | None,
    env_lines: list[str] | None,
    config_path: Path | None,
    config_text: str | None,
    config_backup: bool = True,
) -> None:
    env_backup, env_backup_mode = _read_path_backup(env_path)
    config_backup_bytes, config_backup_mode = _read_path_backup(config_path)

    wrote_env = False
    wrote_config = False
    config_tmp_path: Path | None = None
    config_backup_path: Path | None = None
    try:
        if env_path is not None and env_lines is not None:
            _write_env_atomically(env_path, env_lines)
            wrote_env = True
        if config_path is not None and config_text is not None:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            if config_backup:
                config_backup_path = _create_backup(config_path)
            config_tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
            config_tmp_path.write_text(config_text, encoding="utf-8")
            os.replace(config_tmp_path, config_path)
            wrote_config = True
    except Exception:
        if wrote_env and env_path is not None:
            _restore_path_bytes(env_path, env_backup, env_backup_mode)
        if wrote_config and config_path is not None:
            _restore_path_bytes(config_path, config_backup_bytes, config_backup_mode)
        for cleanup_path in (config_tmp_path, config_backup_path):
            if cleanup_path is None:
                continue
            try:
                cleanup_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def print_env_summary(
    *,
    hermes_home: Path,
    env_state: HermesEnvAuthState,
    env_dry_run: bool,
) -> None:
    print(
        "Hermes Marmot gateway env:"
        f" path={hermes_home / '.env'}"
        f" allowed_users={len(env_state.allowed_users_hex)}"
        f" allow_all_users={str(env_state.allow_all_users).lower()}"
        f" dry_run={str(env_dry_run).lower()}"
    )


def _yaml_string_needs_quotes(text: str) -> bool:
    if not text:
        return True
    lowered = text.lower()
    return (
        lowered in {"true", "false", "null", "~", "yes", "no", "on", "off"}
        or re.fullmatch(r"-?[0-9]+", text) is not None
        or re.fullmatch(r"-?[0-9]+\.[0-9]+", text) is not None
    )


if yaml is not None:
    class _MarmotSafeDumper(yaml.SafeDumper):  # type: ignore[misc, name-defined]
        pass

    def _represent_str(dumper: Any, data: str) -> Any:
        style = "'" if _yaml_string_needs_quotes(data) else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)

    _MarmotSafeDumper.add_representer(str, _represent_str)


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
    if _yaml_string_needs_quotes(text):
        return "'" + text.replace("'", "''") + "'"
    if text and re.fullmatch(r"[A-Za-z0-9_./:@,+-]+", text):
        return text
    return "'" + text.replace("'", "''") + "'"


def _simple_yaml_dump(data: dict[str, Any]) -> str:
    lines: list[str] = []

    def emit_sequence(sequence: list[Any], indent: int) -> None:
        prefix = " " * indent
        for item in sequence:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                emit_mapping(item, indent + 2)
            else:
                lines.append(f"{prefix}- {_format_scalar(item)}")

    def emit_mapping(mapping: dict[str, Any], indent: int) -> None:
        prefix = " " * indent
        for key, value in mapping.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                emit_mapping(value, indent + 2)
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                emit_sequence(value, indent + 2)
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
        return yaml.dump(
            config,
            Dumper=_MarmotSafeDumper,
            sort_keys=False,
            default_flow_style=False,
        )
    return _simple_yaml_dump(config)


def _ensure_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    current = parent.get(key)
    if isinstance(current, dict):
        return current
    replacement: dict[str, Any] = {}
    parent[key] = replacement
    return replacement


def _clean_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    cleaned = [value.strip() for value in values if value and value.strip()]
    return sorted(dict.fromkeys(cleaned))


def _create_backup(config_path: Path) -> Path | None:
    if not config_path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = config_path.with_name(f"{config_path.name}.{stamp}.{os.getpid()}.bak")
    shutil.copy2(config_path, backup_path)
    return backup_path


def prepare_gateway_config(
    *,
    hermes_home: Path,
    platform: str,
    streaming_enabled: bool,
    streaming_transport: str,
    tool_progress: str,
    interim_assistant_messages: bool,
    long_running_notifications: bool,
    busy_ack_detail: bool,
    agent_home: Path | None = None,
    socket_path: Path | None = None,
    account_id_hex: str | None = None,
    welcomer_allowlist: list[str] | None = None,
    profile_name_onboarding: bool | None = None,
    configure_global_streaming: bool = False,
) -> tuple[Path, str]:
    if streaming_transport not in VALID_STREAMING_TRANSPORT:
        valid = ", ".join(sorted(VALID_STREAMING_TRANSPORT))
        raise ValueError(f"streaming transport must be one of: {valid}")
    if tool_progress not in VALID_TOOL_PROGRESS:
        valid = ", ".join(sorted(VALID_TOOL_PROGRESS))
        raise ValueError(f"tool progress must be one of: {valid}")

    config_path = hermes_home / "config.yaml"
    config = load_config(config_path)
    effective_streaming = streaming_enabled and streaming_transport != "off"

    if configure_global_streaming:
        streaming = _ensure_mapping(config, "streaming")
        streaming["enabled"] = streaming_enabled
        streaming["transport"] = streaming_transport

    platform_entries = _ensure_mapping(config, "platforms")
    platform_entry = _ensure_mapping(platform_entries, platform)
    # Persist platform activation in gateway config. The installer cannot
    # assume an externally managed Hermes process inherits MARMOT_HOME or
    # MARMOT_AGENT_SOCKET from its shell environment.
    platform_entry["enabled"] = True
    extra = _ensure_mapping(platform_entry, "extra")
    if agent_home is not None:
        extra["home"] = str(agent_home)
    if socket_path is not None:
        extra["socket_path"] = str(socket_path)
    if account_id_hex:
        extra["account_id_hex"] = account_id_hex.strip()
    cleaned_allowlist = _clean_list(welcomer_allowlist)
    if cleaned_allowlist:
        extra["welcomer_allowlist"] = ",".join(cleaned_allowlist)
    if profile_name_onboarding is not None:
        extra["profile_name_onboarding"] = profile_name_onboarding

    display = _ensure_mapping(config, "display")
    platforms = _ensure_mapping(display, "platforms")
    platform_config = _ensure_mapping(platforms, platform)
    platform_config["streaming"] = effective_streaming
    platform_config["tool_progress"] = tool_progress
    platform_config["interim_assistant_messages"] = interim_assistant_messages
    platform_config["long_running_notifications"] = long_running_notifications
    platform_config["busy_ack_detail"] = busy_ack_detail

    return config_path, dump_config(config)


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
    agent_home: Path | None = None,
    socket_path: Path | None = None,
    account_id_hex: str | None = None,
    welcomer_allowlist: list[str] | None = None,
    profile_name_onboarding: bool | None = None,
    configure_global_streaming: bool = False,
    backup: bool = True,
) -> Path:
    config_path, config_text = prepare_gateway_config(
        hermes_home=hermes_home,
        platform=platform,
        streaming_enabled=streaming_enabled,
        streaming_transport=streaming_transport,
        tool_progress=tool_progress,
        interim_assistant_messages=interim_assistant_messages,
        long_running_notifications=long_running_notifications,
        busy_ack_detail=busy_ack_detail,
        agent_home=agent_home,
        socket_path=socket_path,
        account_id_hex=account_id_hex,
        welcomer_allowlist=welcomer_allowlist,
        profile_name_onboarding=profile_name_onboarding,
        configure_global_streaming=configure_global_streaming,
    )
    commit_env_and_config_transaction(
        env_path=None,
        env_lines=None,
        config_path=config_path,
        config_text=config_text,
        config_backup=backup,
    )
    return config_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", default=os.environ.get("HERMES_HOME", "~/.hermes"))
    parser.add_argument("--platform", default="marmot")
    parser.add_argument("--agent-home", default=os.environ.get("MARMOT_HOME"))
    parser.add_argument("--socket-path", default=os.environ.get("MARMOT_AGENT_SOCKET"))
    parser.add_argument("--account-id-hex", default=os.environ.get("MARMOT_ACCOUNT_ID_HEX"))
    parser.add_argument(
        "--welcomer-allowlist",
        action="append",
        default=[],
        help="Welcomer account id/npub allowlist entry; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--profile-name-onboarding",
        default=os.environ.get("MARMOT_PROFILE_NAME_ONBOARDING"),
    )
    parser.add_argument("--streaming", default=os.environ.get("HERMES_MARMOT_STREAMING", "0"))
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
    parser.add_argument(
        "--configure-global-streaming",
        action="store_true",
        help="Also update Hermes' global streaming block; off by default to preserve other connectors",
    )
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--configure-env",
        action="store_true",
        help="Update $HERMES_HOME/.env Marmot sender authorization variables",
    )
    parser.add_argument(
        "--allow-user",
        action="append",
        default=[],
        help="Allowed Marmot message sender npub or hex account id; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--allow-all-users",
        action="store_true",
        help="Explicitly opt into MARMOT_ALLOW_ALL_USERS=true",
    )
    parser.add_argument(
        "--env-dry-run",
        action="store_true",
        help="Validate and print Hermes .env authorization changes without writing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.env_dry_run and not args.configure_env:
        parser.error("--env-dry-run requires --configure-env")

    try:
        hermes_home = Path(args.home).expanduser()
        allowed_users: list[str] = []
        for value in args.allow_user:
            allowed_users.extend(value.split(","))

        if allowed_users:
            validate_sender_auth_entries(allowed_users)

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
        profile_name_onboarding = (
            None
            if args.profile_name_onboarding is None
            else parse_bool(
                args.profile_name_onboarding,
                name="profile name onboarding",
            )
        )

        env_state: HermesEnvAuthState | None = None
        env_prepared: tuple[Path, list[str]] | None = None
        needs_env = args.configure_env or allowed_users or args.allow_all_users
        if needs_env:
            env_state, env_path, env_lines = prepare_hermes_env(
                hermes_home=hermes_home,
                add_allowed_users=allowed_users,
                allow_all_opt_in=args.allow_all_users,
            )
            if not (args.configure_env and args.env_dry_run):
                env_prepared = (env_path, env_lines)

        if args.configure_env and args.env_dry_run:
            if not args.quiet and env_state is not None:
                print_env_summary(
                    hermes_home=hermes_home,
                    env_state=env_state,
                    env_dry_run=args.env_dry_run,
                )
            return 0

        env_only = args.configure_env and not (
            args.agent_home
            or args.socket_path
            or args.account_id_hex
            or args.welcomer_allowlist
            or args.profile_name_onboarding is not None
            or args.configure_global_streaming
        )
        if env_only:
            if env_prepared is not None:
                _write_env_atomically(env_prepared[0], env_prepared[1])
            if not args.quiet and env_state is not None:
                print_env_summary(
                    hermes_home=hermes_home,
                    env_state=env_state,
                    env_dry_run=args.env_dry_run,
                )
            return 0

        welcomer_allowlist = []
        env_allowlist = os.environ.get("MARMOT_WELCOMER_ALLOWLIST") or os.environ.get(
            "MARMOT_DM_ALLOW_FROM"
        )
        if env_allowlist:
            welcomer_allowlist.extend(env_allowlist.split(","))
        for value in args.welcomer_allowlist:
            welcomer_allowlist.extend(value.split(","))
        config_path, config_text = prepare_gateway_config(
            hermes_home=hermes_home,
            platform=args.platform,
            streaming_enabled=streaming_enabled,
            streaming_transport=args.transport,
            tool_progress=args.tool_progress,
            interim_assistant_messages=interim_assistant_messages,
            long_running_notifications=long_running_notifications,
            busy_ack_detail=busy_ack_detail,
            agent_home=Path(args.agent_home).expanduser() if args.agent_home else None,
            socket_path=Path(args.socket_path).expanduser() if args.socket_path else None,
            account_id_hex=args.account_id_hex,
            welcomer_allowlist=welcomer_allowlist,
            profile_name_onboarding=profile_name_onboarding,
            configure_global_streaming=args.configure_global_streaming,
        )
        env_path, env_lines = env_prepared if env_prepared is not None else (None, None)
        commit_env_and_config_transaction(
            env_path=env_path,
            env_lines=env_lines,
            config_path=config_path,
            config_text=config_text,
            config_backup=not args.no_backup,
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
            f" global_streaming={str(args.configure_global_streaming).lower()}"
        )
        if env_state is not None:
            print_env_summary(
                hermes_home=hermes_home,
                env_state=env_state,
                env_dry_run=args.env_dry_run,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
