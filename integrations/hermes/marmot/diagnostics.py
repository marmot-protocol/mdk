"""Shared Hermes Marmot diagnostic report helpers and live plugin observations.

The collector (`doctor.py`) imports this module without loading the adapter or a
gateway. The running adapter owns the private status socket and lifecycle state.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = 1
DIAGNOSTICS_DIRNAME = "marmot"
DIAGNOSTICS_SOCKET_NAME = "diagnostics.sock"
MAX_FRAME_BYTES = 16 * 1024
IO_TIMEOUT_S = 2.0
MAX_CONCURRENT_REQUESTS = 4
SUBPROCESS_TIMEOUT_S = 3.0
CONNECTOR_TIMEOUT_S = 5.0
DOCTOR_DEADLINE_S = 20.0
MAX_CONFIG_BYTES = 256 * 1024
UNIX_SOCKET_PATH_MAX = 104
CHECK_OWNERS = ("installer", "service", "wn_agent", "hermes_config", "hermes_plugin")
CHECK_PROVENANCE = ("observed", "inferred")
CHECK_STATUSES = ("healthy", "degraded", "fatal", "unknown")
LIFECYCLE_STATES = (
    "starting",
    "awaiting_ack",
    "established",
    "reconnecting",
    "stopped",
    "failed",
)
RECONCILE_STATES = ("not_configured", "pending", "succeeded", "failed")
DISCONNECT_REASONS = (
    "clean_eof",
    "resync_required",
    "timeout",
    "socket_closed",
    "socket_io",
    "unauthorized",
    "transport",
)

REDACT_TOKENS = ("token", "secret", "nsec", "password", "authorization")
INBOUND_MEDIA_KINDS = ("document", "image", "video", "voice")
OUTBOUND_MEDIA_KINDS = ("document", "image", "video", "voice")
ACCOUNT_ID_HEX_LEN = 64
WELCOMER_ALIASES = ("welcomer_allowlist", "welcomerAllowlist", "dm_allow_from", "dmAllowFrom")
WELCOMER_ENV_KEYS = ("MARMOT_WELCOMER_ALLOWLIST", "MARMOT_DM_ALLOW_FROM")
DOTENV_CONNECTOR_KEYS = frozenset(
    {
        "MARMOT_HOME_CHANNEL",
        "MARMOT_HOME_CHANNEL_NAME",
        "MARMOT_AGENT_SOCKET",
        "MARMOT_HOME",
        "MARMOT_ACCOUNT_ID_HEX",
        "MARMOT_AGENT_AUTH_TOKEN",
        "MARMOT_AGENT_AUTH_TOKEN_FILE",
        "MARMOT_WELCOMER_ALLOWLIST",
        "MARMOT_DM_ALLOW_FROM",
        "MARMOT_GROUP_ID_HEX",
        "MARMOT_ALLOWED_USERS",
        "MARMOT_ALLOW_ALL_USERS",
        "MARMOT_INBOUND_MEDIA_DIR",
        "MARMOT_OUTBOUND_MEDIA_DIR",
    }
)
_DOTENV_INTERPOLATION = re.compile(
    r"(?P<escape>\\)?"
    r"\$(?:"
    r"(?P<escaped>\$)|"
    r"(?P<named>[_A-Za-z][_A-Za-z0-9]*)|"
    r"\{(?P<braced>[_A-Za-z][_A-Za-z0-9]*)\}|"
    r"\{(?P<braced_default>[_A-Za-z][_A-Za-z0-9]*):-(?P<default>[^}]*)\}"
    r")"
)


def redacted(text: str) -> str:
    """Return a privacy-safe placeholder; never echo caller-supplied text."""

    del text
    return "<redacted>"


def check(
    check_id: str,
    *,
    owner: str,
    provenance: str,
    status: str,
    code: str,
    value: Any = None,
) -> dict[str, Any]:
    if owner not in CHECK_OWNERS:
        raise ValueError("invalid diagnostic owner")
    if provenance not in CHECK_PROVENANCE:
        raise ValueError("invalid diagnostic provenance")
    if status not in CHECK_STATUSES:
        raise ValueError("invalid diagnostic status")
    return {
        "id": check_id,
        "owner": owner,
        "provenance": provenance,
        "status": status,
        "code": code,
        "value": value,
    }


def report_object(checks: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [item for item in checks if item["id"] != "delivery.probe"]
    if any(item["status"] == "fatal" for item in applicable):
        status = "fatal"
        exit_code = 2
    elif any(item["status"] in {"degraded", "unknown"} for item in applicable):
        status = "degraded"
        exit_code = 1
    else:
        status = "healthy"
        exit_code = 0
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "exit_code": exit_code,
        "checks": checks,
    }


def fatal_helper_report() -> dict[str, Any]:
    return report_object(
        [
            check(
                "release.doctor_runtime",
                owner="installer",
                provenance="observed",
                status="fatal",
                code="helper_unavailable",
            )
        ]
    )


def render_human(report: dict[str, Any]) -> str:
    lines = [
        f"Hermes Marmot doctor: {report.get('status', 'unknown')} (exit {report.get('exit_code', 1)})",
        "Passive observations only. This is not delivery, send, or repair proof.",
    ]
    for item in report.get("checks") or []:
        value = item.get("value")
        rendered = "" if value is None else f" value={_human_value(value)}"
        lines.append(
            f"- {item.get('id')}: {item.get('status')}/{item.get('code')} "
            f"({item.get('owner')}/{item.get('provenance')}){rendered}"
        )
    lines.append(
        "Restart Hermes after plugin or sender-authorization changes; "
        "do not treat inbound receipt as recipient delivery."
    )
    return "\n".join(lines) + "\n"


def _human_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return ",".join(f"{key}={_human_value(item)}" for key, item in sorted(value.items()))
    return "<aggregate>"


def normalize_home_route(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered.startswith("marmot:"):
        lowered = lowered.split(":", 1)[1]
    if not lowered or any(character.isspace() for character in lowered):
        return None
    if len(lowered) % 2 != 0 or any(character not in "0123456789abcdef" for character in lowered):
        return None
    return lowered


def normalize_account_id(value: Any) -> Optional[str]:
    route = normalize_home_route(value)
    if route is None or len(route) != ACCOUNT_ID_HEX_LEN:
        return None
    return route


def parse_config_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().casefold()
    if not text:
        return default
    return text not in {"0", "false", "no", "off", "disabled"}


def env_lookup(name: str, env_values: Optional[dict[str, str]] = None) -> str:
    if env_values is not None:
        return str(env_values.get(name) or "").strip()
    return os.getenv(name, "").strip()


def first_config_value(
    extra: dict[str, Any],
    *keys: str,
    env: Optional[str] = None,
    env_values: Optional[dict[str, str]] = None,
) -> Any:
    if env:
        value = env_lookup(env, env_values)
        if value:
            return value
    for key in keys:
        value = extra.get(key)
        if value:
            return value
    return None


def project_effective_env(
    dotenv_values: Optional[dict[str, str]] = None,
    *,
    environ: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Project Hermes user-dotenv loading without mutating the process.

    The pinned current-candidate loader applies ``~/.hermes/.env`` with
    ``override=True``. Only connector keys are overlaid; other host or managed
    overrides stay unmodeled.
    """

    projected = dict(environ if environ is not None else os.environ)
    for key, value in (dotenv_values or {}).items():
        if key not in DOTENV_CONNECTOR_KEYS:
            continue
        # Hermes load_dotenv(override=True) writes explicit empty assignments.
        projected[key] = str(value).strip()
    return projected


def plugin_settings_from_config(config: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    plugins = config.get("plugins")
    if not isinstance(plugins, dict) or not isinstance(plugins.get("entries"), dict):
        return {}
    plugin = plugins["entries"].get("marmot")
    if not isinstance(plugin, dict) or not isinstance(plugin.get("settings"), dict):
        return {}
    return {
        key: value
        for key, value in plugin["settings"].items()
        if value not in (None, "")
    }


def env_enablement_seed(
    plugin_settings: Optional[dict[str, Any]] = None,
    *,
    env_values: Optional[dict[str, str]] = None,
) -> Optional[dict[str, Any]]:
    """Return the same enablement seed Hermes applies from env plus plugin settings."""

    socket = env_lookup("MARMOT_AGENT_SOCKET", env_values)
    home = env_lookup("MARMOT_HOME", env_values)
    account = env_lookup("MARMOT_ACCOUNT_ID_HEX", env_values)
    group = env_lookup("MARMOT_GROUP_ID_HEX", env_values)
    candidates = env_lookup("MARMOT_QUIC_CANDIDATES", env_values) or env_lookup(
        "MARMOT_QUIC_CANDIDATE", env_values
    )
    seed: dict[str, Any] = {}
    if socket or home:
        if socket:
            seed["socket_path"] = socket
        if home:
            seed["home"] = home
        if account:
            seed["account_id_hex"] = account
        if group:
            seed["group_id_hex"] = group
        if candidates:
            seed["quic_candidates"] = split_config_list(candidates)
        auth_token_file = env_lookup("MARMOT_AGENT_AUTH_TOKEN_FILE", env_values)
        if auth_token_file:
            seed["auth_token_file"] = auth_token_file
        home_channel = env_lookup("MARMOT_HOME_CHANNEL", env_values)
        if home_channel:
            seed["home_channel"] = {
                "chat_id": home_channel,
                "name": env_lookup("MARMOT_HOME_CHANNEL_NAME", env_values) or "Marmot",
            }
    for key in ("socket_path", "home", "account_id_hex", "group_id_hex"):
        value = (plugin_settings or {}).get(key)
        if value not in (None, ""):
            seed.setdefault(key, value)
    plugin_home = (plugin_settings or {}).get("home_channel")
    if plugin_home not in (None, ""):
        seed.setdefault("home_channel", {"chat_id": str(plugin_home), "name": "Marmot"})
    return seed or None


def apply_enablement_seed(
    merged: dict[str, Any],
    seed: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Apply Hermes ``extra.update(seed)`` plus home-channel replacement."""

    extra = dict(merged.get("extra") or {})
    home_channel = merged.get("home_channel")
    home_platform = merged.get("home_platform")
    if not seed:
        return {"extra": extra, "home_channel": home_channel, "home_platform": home_platform}
    applied = dict(seed)
    home = applied.pop("home_channel", None)
    extra.update(applied)
    if isinstance(home, dict) and home.get("chat_id"):
        home_channel = home.get("chat_id")
        home_platform = "marmot"
    return {"extra": extra, "home_channel": home_channel, "home_platform": home_platform}


def split_config_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def parse_dotenv_scalar(raw_value: str) -> str:
    value, _interpolate = _parse_dotenv_scalar(raw_value)
    return value


def _parse_dotenv_scalar(raw_value: str) -> tuple[str, bool]:
    value = raw_value.strip()
    if not value:
        return "", True
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        inner = value[1:] if end == -1 else value[1:end]
        return inner, quote != "'"
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value, True


def interpolate_dotenv_value(value: str, lookup) -> tuple[str, bool]:
    """Expand python-dotenv POSIX variables without sourcing the file.

    Returns ``(expanded, supported)``. Unsupported syntax is left unchanged
    and flagged so callers do not treat the literal as a resolved secret.
    """

    if "${" in value and _DOTENV_INTERPOLATION.search(value) is None:
        return value, False
    parts: list[str] = []
    cursor = 0
    for match in _DOTENV_INTERPOLATION.finditer(value):
        parts.append(value[cursor : match.start()])
        if match.group("escape"):
            parts.append(match.group(0)[1:])
        elif match.group("escaped"):
            parts.append("$")
        elif match.group("named"):
            parts.append(lookup(match.group("named")))
        elif match.group("braced"):
            parts.append(lookup(match.group("braced")))
        else:
            found = lookup(match.group("braced_default"))
            parts.append(found if found else (match.group("default") or ""))
        cursor = match.end()
    parts.append(value[cursor:])
    expanded = "".join(parts)
    if "${" in expanded:
        return expanded, False
    return expanded, True


@dataclass(frozen=True)
class ParsedHermesEnv:
    senders: list[str] = field(default_factory=list)
    allow_all: bool = False
    error: Optional[str] = None
    values: dict[str, str] = field(default_factory=dict)


def identity_digest(value: Optional[str]) -> str:
    if not value:
        return ""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def media_fingerprint_value() -> dict[str, Any]:
    return {
        "inbound": list(INBOUND_MEDIA_KINDS),
        "outbound": list(OUTBOUND_MEDIA_KINDS),
    }


def host_outbound_dispatch_status() -> Optional[bool]:
    module = sys.modules.get("gateway.platforms.base")
    if module is None:
        return None
    return getattr(module, "MediaKind", None) is not None


def media_capability_status(*, host_outbound_dispatch: Optional[bool] = None) -> dict[str, Any]:
    status = media_fingerprint_value()
    if host_outbound_dispatch is None:
        host_outbound_dispatch = host_outbound_dispatch_status()
    status["host_outbound_dispatch"] = host_outbound_dispatch
    return status


def bounded_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def report_exit_code(report: dict[str, Any]) -> int:
    if "exit_code" not in report:
        return 1
    try:
        return int(report["exit_code"])
    except (TypeError, ValueError):
        return 1


def config_fingerprint(fields: dict[str, Any]) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def nonsecret_config_fields(
    *,
    senders: list[str],
    allow_all: bool,
    welcomers: list[str],
    account_id_hex: Optional[str],
    socket_path: Optional[str],
    home_route: Optional[str],
    media: Optional[dict[str, Any]] = None,
    inbound_media_dir: Optional[str] = None,
    outbound_media_dir: Optional[str] = None,
) -> dict[str, Any]:
    normalized_socket = str(Path(socket_path).expanduser()) if socket_path else ""
    inbound = str(Path(inbound_media_dir).expanduser()) if inbound_media_dir else ""
    outbound = str(Path(outbound_media_dir).expanduser()) if outbound_media_dir else ""
    return {
        "senders": sorted({item.lower() for item in senders if item}),
        "allow_all": bool(allow_all),
        "welcomers": sorted({item.lower() for item in welcomers if item}),
        "account": identity_digest(account_id_hex),
        "socket": identity_digest(normalized_socket),
        "home_route": home_route or "",
        "media": media if media is not None else media_fingerprint_value(),
        "inbound_media_dir": identity_digest(inbound),
        "outbound_media_dir": identity_digest(outbound),
    }


def resolve_marmot_home(
    extra: dict[str, Any],
    socket_path: str | Path | None = None,
    *,
    env_values: Optional[dict[str, str]] = None,
    fallback_home: Optional[Path] = None,
) -> Path:
    home = first_config_value(extra, "home", "marmot_home", env="MARMOT_HOME", env_values=env_values)
    if home:
        return Path(str(home)).expanduser()
    if socket_path not in (None, ""):
        return Path(str(socket_path)).expanduser().parent.parent
    if fallback_home is not None:
        return Path(fallback_home).expanduser()
    return Path("~/.marmot").expanduser()


def resolve_inbound_media_dir(
    extra: dict[str, Any],
    socket_path: str | Path | None = None,
    *,
    env_values: Optional[dict[str, str]] = None,
    fallback_home: Optional[Path] = None,
) -> Path:
    configured = first_config_value(
        extra, "inbound_media_dir", env="MARMOT_INBOUND_MEDIA_DIR", env_values=env_values
    )
    if configured:
        return Path(str(configured)).expanduser()
    return (
        resolve_marmot_home(
            extra, socket_path, env_values=env_values, fallback_home=fallback_home
        )
        / "dev"
        / "inbound-media"
    )


def resolve_outbound_media_dir(
    extra: dict[str, Any],
    socket_path: str | Path | None = None,
    *,
    env_values: Optional[dict[str, str]] = None,
    fallback_home: Optional[Path] = None,
) -> Path:
    configured = first_config_value(
        extra, "outbound_media_dir", env="MARMOT_OUTBOUND_MEDIA_DIR", env_values=env_values
    )
    if configured:
        return Path(str(configured)).expanduser()
    return (
        resolve_marmot_home(
            extra, socket_path, env_values=env_values, fallback_home=fallback_home
        )
        / "dev"
        / "outbound-media"
    )


def merge_hermes_marmot_config(config: Optional[dict[str, Any]]) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    home_channel: Any = None
    home_platform: Optional[str] = None
    if not isinstance(config, dict):
        return {"extra": extra, "home_channel": None, "home_platform": None}
    platforms = config.get("platforms")
    if isinstance(platforms, dict) and isinstance(platforms.get("marmot"), dict):
        platform = platforms["marmot"]
        home_channel, home_platform = _home_channel_fields(platform.get("home_channel"))
        nested = platform.get("extra")
        if isinstance(nested, dict):
            extra.update(nested)
        else:
            for key, value in platform.items():
                if key in {"extra", "home_channel", "enabled", "name"} or value in (None, ""):
                    continue
                extra.setdefault(key, value)
    plugins = config.get("plugins")
    if isinstance(plugins, dict) and isinstance(plugins.get("entries"), dict):
        plugin = plugins["entries"].get("marmot")
        if isinstance(plugin, dict) and isinstance(plugin.get("settings"), dict):
            settings = plugin["settings"]
            for key, value in settings.items():
                if value in (None, "") or key in extra:
                    continue
                extra[key] = value
            if home_channel in (None, ""):
                home_channel, home_platform = _home_channel_fields(settings.get("home_channel"))
    return {
        "extra": extra,
        "home_channel": home_channel,
        "home_platform": home_platform,
    }


def _home_channel_fields(raw: Any) -> tuple[Any, Optional[str]]:
    if isinstance(raw, dict):
        platform = raw.get("platform")
        return raw.get("chat_id"), str(platform).strip().lower() if platform not in (None, "") else None
    if isinstance(raw, str):
        return raw, None
    return None, None


def resolve_home_route(
    extra: dict[str, Any],
    *,
    home_channel: Any = None,
    home_platform: Optional[str] = None,
    override: Optional[str] = None,
    env_values: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], Optional[str]]:
    if override:
        route = normalize_home_route(override)
        return route, "invalid" if route is None else None
    if home_platform and home_platform not in {"marmot"}:
        return None, "wrong_platform"
    if isinstance(home_channel, dict) or home_channel in (None, ""):
        raw = home_channel if isinstance(home_channel, dict) else extra.get("home_channel")
        if raw not in (None, ""):
            home_channel, extra_platform = _home_channel_fields(raw)
            if extra_platform:
                home_platform = extra_platform
    if home_platform and home_platform not in {"marmot"}:
        return None, "wrong_platform"
    if home_channel in (None, ""):
        env_home = env_lookup("MARMOT_HOME_CHANNEL", env_values)
        if env_home:
            home_channel = env_home
    if home_channel in (None, ""):
        return None, None
    route = normalize_home_route(home_channel)
    return route, "invalid" if route is None else None


def resolve_account_id(
    extra: dict[str, Any],
    *,
    override: Optional[str] = None,
    env_values: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], str]:
    candidate = override if override not in (None, "") else first_config_value(
        extra, "account_id_hex", "account", env="MARMOT_ACCOUNT_ID_HEX", env_values=env_values
    )
    if candidate in (None, ""):
        return None, "auto"
    account = normalize_account_id(candidate)
    if account is None:
        return None, "invalid"
    return account, "explicit"


def resolve_socket_path(
    extra: dict[str, Any],
    *,
    fallback: Optional[Path] = None,
    env_values: Optional[dict[str, str]] = None,
) -> Optional[Path]:
    configured = first_config_value(
        extra, "socket_path", "agent_socket", "socket", env="MARMOT_AGENT_SOCKET", env_values=env_values
    )
    if configured:
        return Path(str(configured)).expanduser()
    home = first_config_value(extra, "home", "marmot_home", env="MARMOT_HOME", env_values=env_values)
    if home:
        return Path(str(home)).expanduser() / "dev" / "wn-agent.sock"
    return Path(fallback).expanduser() if fallback is not None else None


def resolve_auth_token(
    extra: dict[str, Any],
    *,
    token: Optional[str] = None,
    token_file: Optional[str] = None,
    env_values: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], Optional[str]]:
    if token not in (None, ""):
        stripped = str(token).strip()
        return (stripped or None), None if stripped else "empty"
    configured = first_config_value(
        extra, "auth_token", "agent_auth_token", env="MARMOT_AGENT_AUTH_TOKEN", env_values=env_values
    )
    if configured not in (None, ""):
        stripped = str(configured).strip()
        return (stripped or None), None if stripped else "empty"
    if token_file not in (None, ""):
        return _read_auth_token_file(token_file)
    configured_file = first_config_value(
        extra,
        "auth_token_file",
        "agent_auth_token_file",
        env="MARMOT_AGENT_AUTH_TOKEN_FILE",
        env_values=env_values,
    )
    if configured_file in (None, ""):
        return None, None
    return _read_auth_token_file(configured_file)


def _read_auth_token_file(path_value: Any) -> tuple[Optional[str], Optional[str]]:
    path = Path(str(path_value)).expanduser()
    try:
        loaded = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None, "unreadable"
    return (loaded or None), None if loaded else "empty"


def resolve_welcomers(
    extra: dict[str, Any],
    *,
    env_values: Optional[dict[str, str]] = None,
) -> list[str]:
    for key in WELCOMER_ALIASES:
        if key in extra:
            return split_config_list(extra[key])
    for name in WELCOMER_ENV_KEYS:
        value = env_lookup(name, env_values)
        if value:
            return split_config_list(value)
    return []


@dataclass
class PluginObservations:
    state: str = "stopped"
    last_disconnect_reason: Optional[str] = None
    reconnect_count: int = 0
    resync_count: int = 0
    recovery_count: int = 0
    reconciliation: str = "not_configured"
    plugin_version: Optional[str] = None
    loaded_fingerprint: Optional[str] = None
    sender_count: int = 0
    allow_all: bool = False
    welcomer_count: int = 0
    account_selected: bool = False
    home_configured: bool = False
    loaded_home_digest: str = ""
    media: dict[str, Any] = field(default_factory=dict)
    _recovery_pending: bool = False

    def snapshot(
        self,
        expected_fingerprint: Optional[str] = None,
        expected_home_digest: Optional[str] = None,
    ) -> dict[str, Any]:
        match: Optional[bool] = None
        if expected_fingerprint and self.loaded_fingerprint:
            match = expected_fingerprint == self.loaded_fingerprint
        home_matches: Optional[bool] = None
        if expected_home_digest:
            home_matches = bool(self.loaded_home_digest) and expected_home_digest == self.loaded_home_digest
        elif self.loaded_home_digest:
            home_matches = None
        return {
            "schema_version": SCHEMA_VERSION,
            "lifecycle": self.state,
            "last_disconnect_reason": self.last_disconnect_reason,
            "reconnect_count": self.reconnect_count,
            "resync_count": self.resync_count,
            "recovery_count": self.recovery_count,
            "reconciliation": self.reconciliation,
            "config_matches": match,
            "sender_count": self.sender_count,
            "allow_all": self.allow_all,
            "welcomer_count": self.welcomer_count,
            "account_selected": self.account_selected,
            "home_configured": self.home_configured,
            "home_matches": home_matches,
            "media_ready": bool(self.media.get("inbound") or self.media.get("outbound") or self.media),
            "plugin_version": self.plugin_version,
        }

    def mark(self, state: str, *, reason: Optional[str] = None) -> None:
        if state not in LIFECYCLE_STATES:
            state = "failed"
        previous = self.state
        if state == "reconnecting" and previous == "established":
            self.reconnect_count += 1
            self._recovery_pending = True
        if state == "failed" and previous not in {"failed", "stopped"}:
            self._recovery_pending = True
        if state == "awaiting_ack" and previous in {"reconnecting", "failed"}:
            self._recovery_pending = True
        if state == "established" and (previous in {"reconnecting", "failed"} or self._recovery_pending):
            self.recovery_count += 1
            self._recovery_pending = False
        if state == "stopped":
            self._recovery_pending = False
        if reason == "resync_required":
            self.resync_count += 1
        if reason in DISCONNECT_REASONS:
            self.last_disconnect_reason = reason
        self.state = state


class DiagnosticSocketServer:
    def __init__(self, path: Path, observations: PluginObservations):
        self.path = path
        self.observations = observations
        self._server: Optional[asyncio.AbstractServer] = None
        self._limiter = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._bound_inode: Optional[int] = None

    async def start(self) -> bool:
        try:
            sock = _bind_private_socket(self.path)
        except OSError:
            return False
        self._bound_inode = _socket_inode(self.path)
        self._server = await asyncio.start_unix_server(self._handle, sock=sock)
        return True

    async def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        _cleanup_owned_socket(self.path, self._bound_inode)
        self._bound_inode = None

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            async with self._limiter:
                line = await asyncio.wait_for(reader.readline(), timeout=IO_TIMEOUT_S)
                if not line or len(line) > MAX_FRAME_BYTES:
                    return
                try:
                    request = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return
                if not isinstance(request, dict) or request.get("schema_version") != SCHEMA_VERSION:
                    return
                if request.get("type") != "status":
                    return
                fingerprint = request.get("config_fingerprint")
                if fingerprint is not None and not isinstance(fingerprint, str):
                    fingerprint = None
                home_digest = request.get("home_route_digest")
                if home_digest is not None and not isinstance(home_digest, str):
                    home_digest = None
                payload = json.dumps(
                    self.observations.snapshot(fingerprint, expected_home_digest=home_digest),
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8") + b"\n"
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=IO_TIMEOUT_S)
        except (asyncio.TimeoutError, OSError, ValueError):
            return
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=IO_TIMEOUT_S)
            except (asyncio.TimeoutError, OSError):
                return


def diagnostics_socket_path(hermes_home: Path) -> Path:
    return Path(hermes_home).expanduser() / DIAGNOSTICS_DIRNAME / DIAGNOSTICS_SOCKET_NAME


def _bind_private_socket(path: Path) -> socket.socket:
    parent = path.parent
    if not parent.exists():
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o700)
    _require_private_dir(parent)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not stat.S_ISSOCK(path.lstat().st_mode):
            raise OSError("foreign diagnostics path")
        if _socket_is_live(path):
            raise OSError("live diagnostics endpoint")
        path.unlink()
    staged_fd, staged_name = tempfile.mkstemp(
        prefix=".diagnostics.", suffix=".sock", dir=parent
    )
    os.close(staged_fd)
    staged = Path(staged_name)
    staged.unlink(missing_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(staged))
        os.chmod(staged, 0o600)
        os.rename(staged, path)
        os.chmod(path, 0o600)
        sock.listen(MAX_CONCURRENT_REQUESTS)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        staged.unlink(missing_ok=True)
        raise


def _require_private_dir(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError("diagnostics parent is not a directory")
    if info.st_uid != os.getuid():
        raise OSError("diagnostics parent owner mismatch")
    if info.st_mode & 0o077:
        raise OSError("diagnostics parent is not private")


def _socket_is_live(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _socket_inode(path: Path) -> Optional[int]:
    try:
        return path.lstat().st_ino
    except OSError:
        return None


def _cleanup_owned_socket(path: Path, inode: Optional[int]) -> None:
    if inode is None:
        return
    try:
        current = path.lstat()
    except OSError:
        return
    if current.st_ino != inode or not stat.S_ISSOCK(current.st_mode):
        return
    path.unlink(missing_ok=True)


def inspect_path(path: Path, *, expect_dir: bool = False, expect_socket: bool = False) -> dict[str, Any]:
    if path.is_symlink():
        return {"code": "symlink", "status": "fatal"}
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"code": "missing", "status": "unknown"}
    if expect_socket and not stat.S_ISSOCK(info.st_mode):
        return {"code": "not_socket", "status": "fatal"}
    if expect_dir and not stat.S_ISDIR(info.st_mode):
        return {"code": "not_directory", "status": "fatal"}
    if info.st_uid != os.getuid():
        return {"code": "unsafe_owner", "status": "fatal"}
    if info.st_mode & 0o077:
        return {"code": "unsafe_mode", "status": "fatal"}
    return {"code": "present", "status": "healthy", "mode": info.st_mode & 0o777}


def bounded_run(command: list[str], *, timeout: float = SUBPROCESS_TIMEOUT_S) -> Optional[str]:
    import subprocess

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={key: value for key, value in os.environ.items() if key not in {"PYTHONPATH"}},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout[:4096]


def load_configure_helper() -> Any:
    try:
        from . import configure_gateway as helper

        return helper
    except ImportError:
        pass
    script = Path(__file__).resolve().parents[3] / "scripts" / "hermes_marmot_configure_gateway.py"
    if not script.is_file():
        return None
    import importlib.util

    spec = importlib.util.spec_from_file_location("hermes_marmot_configure_gateway", script)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_config_safely(path: Path) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    if not path.exists():
        return None, "missing"
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return None, "oversized"
        helper = load_configure_helper()
        if helper is None:
            return None, "helper_unavailable"
        if getattr(helper, "yaml", None) is None:
            text = path.read_text(encoding="utf-8")
            if any(token in text for token in ("\t", "&", "*", "|", ">", "!")):
                return None, "unsupported_yaml"
        loaded = helper.load_config(path)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None, "invalid"
    if not isinstance(loaded, dict):
        return None, "invalid"
    return loaded, None


def parse_dotenv_assignments(
    text: str,
    *,
    environ: Optional[dict[str, str]] = None,
) -> tuple[dict[str, str], Optional[str]]:
    raw: dict[str, tuple[str, bool]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if key not in DOTENV_CONNECTOR_KEYS:
            continue
        raw[key] = _parse_dotenv_scalar(value)
    source = environ if environ is not None else os.environ
    parsed = {key: item[0] for key, item in raw.items()}

    def lookup(name: str) -> str:
        if name in parsed:
            return parsed[name]
        return str(source.get(name) or "")

    values: dict[str, str] = {}
    unsupported = False
    for key, (value, interpolate) in raw.items():
        if not interpolate:
            values[key] = value
            continue
        expanded, supported = interpolate_dotenv_value(value, lookup)
        if not supported:
            unsupported = True
            continue
        values[key] = expanded
    return values, ("unsupported" if unsupported else None)


def parse_env_safely(path: Path) -> ParsedHermesEnv:
    if not path.exists():
        return ParsedHermesEnv(error="missing")
    interpolation_error: Optional[str] = None
    try:
        text = path.read_text(encoding="utf-8")
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            return ParsedHermesEnv(error="oversized")
        values, interpolation_error = parse_dotenv_assignments(text)
    except (OSError, UnicodeError, ValueError, TypeError):
        return ParsedHermesEnv(error="invalid")
    helper = load_configure_helper()
    if helper is None:
        return ParsedHermesEnv(error="helper_unavailable", values=values)
    try:
        auth = helper.read_hermes_env_auth_from_lines(text.splitlines())
    except (OSError, UnicodeError, ValueError, TypeError):
        return ParsedHermesEnv(error="invalid", values=values)
    return ParsedHermesEnv(
        senders=list(auth.allowed_users_hex),
        allow_all=bool(auth.allow_all_users),
        values=values,
        error=interpolation_error,
    )


async def read_plugin_status(
    hermes_home: Path,
    *,
    config_fingerprint_hex: Optional[str] = None,
    expected_home_digest: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    path = diagnostics_socket_path(hermes_home)
    if path.is_symlink() or not path.exists():
        return None
    try:
        if not stat.S_ISSOCK(path.lstat().st_mode):
            return None
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path),
            timeout=IO_TIMEOUT_S,
        )
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        payload = {"schema_version": SCHEMA_VERSION, "type": "status"}
        if config_fingerprint_hex:
            payload["config_fingerprint"] = config_fingerprint_hex
        if expected_home_digest:
            payload["home_route_digest"] = expected_home_digest
        writer.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        await asyncio.wait_for(writer.drain(), timeout=IO_TIMEOUT_S)
        line = await asyncio.wait_for(reader.readline(), timeout=IO_TIMEOUT_S)
        if not line or len(line) > MAX_FRAME_BYTES:
            return None
        data = json.loads(line.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            return None
        return data
    except (OSError, asyncio.TimeoutError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=IO_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError):
            pass


def plugin_version_from_manifest(plugin_dir: Path) -> Optional[str]:
    path = plugin_dir / "plugin.yaml"
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip("'\"") or None
    return None
