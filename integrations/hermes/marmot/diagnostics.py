"""Shared Hermes Marmot diagnostic report helpers and live plugin observations.

The collector (`doctor.py`) imports this module without loading the adapter or a
gateway. The running adapter owns the private status socket and lifecycle state.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
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
    media: dict[str, Any],
) -> dict[str, Any]:
    return {
        "senders": sorted({item.lower() for item in senders if item}),
        "allow_all": bool(allow_all),
        "welcomers": sorted({item.lower() for item in welcomers if item}),
        "account_selected": bool(account_id_hex),
        "socket_configured": bool(socket_path),
        "home_route": home_route or "",
        "media": media,
    }


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
    media: dict[str, Any] = field(default_factory=dict)

    def snapshot(self, expected_fingerprint: Optional[str] = None) -> dict[str, Any]:
        match: Optional[bool] = None
        if expected_fingerprint and self.loaded_fingerprint:
            match = expected_fingerprint == self.loaded_fingerprint
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
            "media_ready": bool(self.media),
            "plugin_version": self.plugin_version,
        }

    def mark(self, state: str, *, reason: Optional[str] = None) -> None:
        if state not in LIFECYCLE_STATES:
            state = "failed"
        if state == "reconnecting" and self.state == "established":
            self.reconnect_count += 1
        if state == "established" and self.state in {"reconnecting", "failed"}:
            self.recovery_count += 1
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

    async def start(self) -> None:
        try:
            sock = _bind_private_socket(self.path)
        except OSError:
            return
        self._bound_inode = _socket_inode(self.path)
        self._server = await asyncio.start_unix_server(self._handle, sock=sock)

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
                payload = json.dumps(
                    self.observations.snapshot(fingerprint),
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8") + b"\n"
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=IO_TIMEOUT_S)
        except (asyncio.TimeoutError, OSError):
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


def parse_env_safely(path: Path) -> tuple[list[str], bool, Optional[str]]:
    if not path.exists():
        return [], False, "missing"
    helper = load_configure_helper()
    if helper is None:
        return [], False, "helper_unavailable"
    try:
        text = path.read_text(encoding="utf-8")
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            return [], False, "oversized"
        auth = helper.read_hermes_env_auth_from_lines(text.splitlines())
    except (OSError, UnicodeError, ValueError, TypeError):
        return [], False, "invalid"
    return list(auth.allowed_users_hex), bool(auth.allow_all_users), None


async def read_plugin_status(
    hermes_home: Path,
    *,
    config_fingerprint_hex: Optional[str] = None,
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
            return None


def plugin_version_from_manifest(plugin_dir: Path) -> Optional[str]:
    path = plugin_dir / "plugin.yaml"
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip("'\"") or None
    return None
