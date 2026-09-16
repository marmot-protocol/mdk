#!/usr/bin/env python3
"""Privacy-safe, non-mutating Hermes Marmot installation doctor."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

from . import diagnostics as diag


DELIVERY_CHECK = diag.check(
    "delivery.probe",
    owner="installer",
    provenance="observed",
    status="unknown",
    code="not_probed",
)


def collect(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    marmot_home = Path(args.home).expanduser()
    hermes_home = Path(args.hermes_home).expanduser()
    plugin_dir = Path(args.plugin_dir).expanduser()
    socket_path = Path(args.socket).expanduser()
    prefix = Path(args.prefix).expanduser()
    service_name = args.service_name
    launchd_label = args.launchd_label

    installed_plugin = diag.plugin_version_from_manifest(plugin_dir)
    checks.append(_release_check("release.plugin_version", installed_plugin))
    binary_version = _binary_version(prefix)
    checks.append(_release_check("release.binary_version", binary_version))
    manifest_version = _manifest_version(plugin_dir)
    checks.append(_release_check("release.manifest_version", manifest_version))

    checks.extend(_service_checks(service_name, launchd_label, args.install_service))
    checks.append(_socket_check(socket_path))
    checks.extend(_file_checks(marmot_home))

    config_path = hermes_home / "config.yaml"
    env_path = hermes_home / ".env"
    config, config_error = diag.parse_config_safely(config_path)
    senders, allow_all, env_error = diag.parse_env_safely(env_path)
    marmot_config = _marmot_platform_config(config)
    home_route = _configured_home_route(marmot_config, args.group_id_hex)
    account_hex = _configured_account(marmot_config, args.account_id_hex)
    socket_from_config = _configured_socket(marmot_config, socket_path)
    welcomers = _configured_welcomers(marmot_config)
    media = {"outbound": True, "inbound": True}
    fingerprint_fields = diag.nonsecret_config_fields(
        senders=senders,
        allow_all=allow_all,
        welcomers=welcomers,
        account_id_hex=account_hex,
        socket_path=str(socket_from_config) if socket_from_config else None,
        home_route=home_route,
        media=media,
    )
    fingerprint = diag.config_fingerprint(fingerprint_fields) if config_error is None else None

    checks.extend(_config_checks(config_error, env_error, senders, allow_all, home_route))
    connector = _connector_report(
        socket_path,
        account_hex,
        home_route,
        args.auth_token,
        args.auth_token_file,
    )
    checks.extend(_connector_checks(connector, home_route, account_hex, binary_version))
    live = asyncio.run(diag.read_plugin_status(hermes_home, config_fingerprint_hex=fingerprint))
    checks.extend(_plugin_checks(live, installed_plugin, home_route))
    checks.append(DELIVERY_CHECK)
    return diag.report_object(checks)


def _release_check(check_id: str, version: Optional[str]) -> dict[str, Any]:
    if version:
        return diag.check(
            check_id,
            owner="installer",
            provenance="observed",
            status="healthy",
            code="present",
            value=version,
        )
    return diag.check(
        check_id,
        owner="installer",
        provenance="observed",
        status="unknown",
        code="missing",
    )


def _manifest_version(plugin_dir: Path) -> Optional[str]:
    path = plugin_dir / "manifest.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    version = payload.get("artifact_version") or payload.get("workspace_version")
    return str(version) if version else None


def _binary_version(prefix: Path) -> Optional[str]:
    binary = prefix / "bin" / "wn-agent"
    if not binary.is_file():
        return None
    output = diag.bounded_run([str(binary), "--version"])
    if not output:
        return None
    for token in output.split():
        if token[0].isdigit():
            return token.strip()
    return None


def _service_checks(
    service_name: str,
    launchd_label: str,
    install_service: bool,
) -> list[dict[str, Any]]:
    systemd = diag.bounded_run(
        [
            "systemctl",
            "--user",
            "show",
            f"{service_name}.service",
            "--property=ActiveState,SubState,UnitFileState,LoadState,Type",
        ]
    )
    if systemd is not None:
        properties = _parse_unit_properties(systemd)
        active = properties.get("ActiveState")
        if active == "active":
            status, code = "healthy", "running"
        elif active == "inactive":
            status, code = "fatal", "stopped"
        else:
            status, code = "unknown", "unknown"
        return [
            diag.check(
                "service.manager",
                owner="service",
                provenance="observed",
                status="healthy",
                code="systemd_user",
            ),
            diag.check(
                "service.state",
                owner="service",
                provenance="observed",
                status=status,
                code=code,
                value={"active": bool(active == "active")},
            ),
        ]
    launchd = diag.bounded_run(["launchctl", "print", f"gui/{os.getuid()}/{launchd_label}"])
    if launchd is not None:
        running = "state = running" in launchd.lower() or "pid = " in launchd.lower()
        return [
            diag.check(
                "service.manager",
                owner="service",
                provenance="observed",
                status="healthy",
                code="launchd",
            ),
            diag.check(
                "service.state",
                owner="service",
                provenance="observed",
                status="healthy" if running else "fatal",
                code="running" if running else "stopped",
            ),
        ]
    code = "not_managed" if not install_service else "unknown"
    return [
        diag.check(
            "service.manager",
            owner="service",
            provenance="observed",
            status="unknown",
            code=code,
        ),
        diag.check(
            "service.state",
            owner="service",
            provenance="observed",
            status="unknown",
            code="unknown",
        ),
    ]


def _parse_unit_properties(text: str) -> dict[str, str]:
    allowed = {"ActiveState", "SubState", "UnitFileState", "LoadState", "Type"}
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in allowed:
            values[key] = value.strip()
    return values


def _socket_check(path: Path) -> dict[str, Any]:
    inspected = diag.inspect_path(path, expect_socket=True)
    status = inspected["status"]
    code = inspected["code"]
    if code == "missing":
        status = "fatal"
        code = "missing"
    return diag.check(
        "socket.control",
        owner="installer",
        provenance="observed",
        status=status,
        code=code,
    )


def _file_checks(marmot_home: Path) -> list[dict[str, Any]]:
    checks = []
    for name, relative in (
        ("files.home", Path()),
        ("files.inbound_dir", Path("dev") / "inbound-media"),
        ("files.outbound_dir", Path("dev") / "outbound-media"),
        ("files.staging_dir", Path("dev") / "media-staging"),
    ):
        path = marmot_home / relative if relative.parts else marmot_home
        inspected = diag.inspect_path(path, expect_dir=True)
        code = inspected["code"]
        status = inspected["status"]
        if code == "missing" and name != "files.home":
            status, code = "unknown", "not_created"
        elif code == "missing":
            status, code = "fatal", "missing"
        checks.append(
            diag.check(
                name,
                owner="installer",
                provenance="observed",
                status=status,
                code=code,
            )
        )
    return checks


def _marmot_platform_config(config: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    platforms = config.get("platforms")
    if isinstance(platforms, dict) and isinstance(platforms.get("marmot"), dict):
        extra = platforms["marmot"].get("extra")
        if isinstance(extra, dict):
            return extra
        return platforms["marmot"]
    plugins = config.get("plugins")
    if isinstance(plugins, dict):
        entries = plugins.get("entries")
        if isinstance(entries, dict) and isinstance(entries.get("marmot"), dict):
            settings = entries["marmot"].get("settings")
            if isinstance(settings, dict):
                return settings
    return {}


def _configured_home_route(extra: dict[str, Any], override: Optional[str]) -> Optional[str]:
    if override:
        return diag.normalize_home_route(override)
    for key in ("group_id_hex", "group"):
        route = diag.normalize_home_route(extra.get(key))
        if route:
            return route
    home_channel = extra.get("home_channel")
    if isinstance(home_channel, dict):
        return diag.normalize_home_route(home_channel.get("chat_id"))
    if isinstance(home_channel, str):
        return diag.normalize_home_route(home_channel)
    return None


def _configured_account(extra: dict[str, Any], override: Optional[str]) -> Optional[str]:
    candidate = override or extra.get("account_id_hex") or extra.get("account")
    route = diag.normalize_home_route(candidate)
    return route if route and len(route) == 64 else None


def _configured_socket(extra: dict[str, Any], fallback: Path) -> Optional[Path]:
    raw = extra.get("socket_path") or extra.get("agent_socket") or extra.get("socket")
    if raw:
        return Path(str(raw)).expanduser()
    return fallback


def _configured_welcomers(extra: dict[str, Any]) -> list[str]:
    raw = extra.get("welcomer_allowlist") or extra.get("allow_welcomers") or []
    if isinstance(raw, str):
        raw = [item.strip() for item in raw.split(",") if item.strip()]
    if not isinstance(raw, list):
        return []
    values = []
    for item in raw:
        normalized = diag.normalize_home_route(item)
        if normalized:
            values.append(normalized)
    return values


def _config_checks(
    config_error: Optional[str],
    env_error: Optional[str],
    senders: list[str],
    allow_all: bool,
    home_route: Optional[str],
) -> list[dict[str, Any]]:
    checks = []
    if config_error == "missing":
        checks.append(
            diag.check(
                "authorization.config",
                owner="hermes_config",
                provenance="observed",
                status="unknown",
                code="missing",
            )
        )
    elif config_error:
        checks.append(
            diag.check(
                "authorization.config",
                owner="hermes_config",
                provenance="observed",
                status="fatal",
                code=config_error,
            )
        )
    else:
        checks.append(
            diag.check(
                "authorization.config",
                owner="hermes_config",
                provenance="observed",
                status="healthy",
                code="present",
            )
        )
    if env_error == "missing":
        auth_status, auth_code = ("unknown", "missing") if not (senders or allow_all) else ("healthy", "present")
    elif env_error:
        auth_status, auth_code = "fatal", env_error
    elif allow_all or senders:
        auth_status, auth_code = "healthy", "allow_any" if allow_all else "configured"
    else:
        auth_status, auth_code = "degraded", "empty"
    checks.append(
        diag.check(
            "authorization.senders",
            owner="hermes_config",
            provenance="observed",
            status=auth_status,
            code=auth_code,
            value={"sender_count": len(senders), "allow_all": allow_all},
        )
    )
    if home_route:
        checks.append(
            diag.check(
                "home.syntax",
                owner="hermes_config",
                provenance="observed",
                status="healthy",
                code="valid",
                value={"hex_chars": len(home_route)},
            )
        )
        checks.append(
            diag.check(
                "home.configured_route",
                owner="hermes_config",
                provenance="observed",
                status="healthy",
                code="present",
            )
        )
    else:
        checks.append(
            diag.check(
                "home.syntax",
                owner="hermes_config",
                provenance="observed",
                status="degraded",
                code="missing",
            )
        )
        checks.append(
            diag.check(
                "home.configured_route",
                owner="hermes_config",
                provenance="observed",
                status="degraded",
                code="missing",
            )
        )
    return checks


def _connector_report(
    socket_path: Path,
    account_hex: Optional[str],
    home_route: Optional[str],
    auth_token: Optional[str],
    auth_token_file: Optional[str],
) -> Optional[dict[str, Any]]:
    try:
        from .agent_control import AgentControlError, MarmotAgentControlClient
    except Exception:
        return {"unsupported": True}
    token = auth_token
    if not token and auth_token_file:
        try:
            token = Path(auth_token_file).read_text(encoding="utf-8").strip() or None
        except OSError:
            token = None

    async def _request() -> dict[str, Any]:
        client = MarmotAgentControlClient(socket_path, request_timeout=diag.CONNECTOR_TIMEOUT_S, auth_token=token)
        payload: dict[str, Any] = {"type": "diagnostic_status"}
        if account_hex:
            payload["account_id_hex"] = account_hex
        if home_route:
            payload["home_group_id_hex"] = home_route
        try:
            return await client.request(payload, timeout=diag.CONNECTOR_TIMEOUT_S)
        except AgentControlError as exc:
            return {"error_code": exc.code}

    try:
        return asyncio.run(_request())
    except Exception:
        return {"error_code": "connect_failed"}


def _connector_checks(
    response: Optional[dict[str, Any]],
    home_route: Optional[str],
    account_hex: Optional[str],
    binary_version: Optional[str],
) -> list[dict[str, Any]]:
    if response is None:
        return [
            diag.check(
                "account.selection",
                owner="wn_agent",
                provenance="observed",
                status="unknown",
                code="unreachable",
            )
        ]
    if response.get("unsupported"):
        return [_unsupported("account.selection"), _unsupported("key_package.availability")]
    error = response.get("error_code")
    if error == "unauthorized":
        return [
            diag.check(
                "account.selection",
                owner="wn_agent",
                provenance="observed",
                status="fatal",
                code="unauthorized",
            )
        ]
    if error in {"unexpected_response", "protocol_error"}:
        return [_unsupported("account.selection"), _unsupported("release.running_version")]
    if error:
        return [
            diag.check(
                "account.selection",
                owner="wn_agent",
                provenance="observed",
                status="fatal",
                code="unreachable",
            )
        ]
    if response.get("type") != "diagnostic_status":
        return [_unsupported("account.selection")]
    report = response.get("report")
    if not isinstance(report, dict):
        return [_unsupported("account.selection")]
    checks = []
    running = report.get("connector_version")
    if running:
        checks.append(
            diag.check(
                "release.running_version",
                owner="wn_agent",
                provenance="observed",
                status="healthy",
                code="present",
                value=str(running),
            )
        )
        if binary_version and binary_version != str(running):
            checks.append(
                diag.check(
                    "release.compatibility",
                    owner="installer",
                    provenance="inferred",
                    status="degraded",
                    code="mismatch",
                )
            )
        else:
            checks.append(
                diag.check(
                    "release.compatibility",
                    owner="installer",
                    provenance="inferred",
                    status="healthy" if binary_version else "unknown",
                    code="matching" if binary_version else "unknown",
                )
            )
    else:
        checks.append(
            diag.check(
                "release.running_version",
                owner="wn_agent",
                provenance="observed",
                status="unknown",
                code="unknown",
            )
        )
    selection = report.get("selection")
    selection_status = {
        "selected": ("healthy", "selected"),
        "none": ("fatal", "none"),
        "ambiguous": ("fatal", "ambiguous"),
        "explicit_unavailable": ("fatal", "explicit_unavailable"),
    }.get(str(selection), ("unknown", "unknown"))
    checks.append(
        diag.check(
            "account.selection",
            owner="wn_agent",
            provenance="observed",
            status=selection_status[0],
            code=selection_status[1],
            value={
                "account_count": report.get("account_count"),
                "local_signing_account_count": report.get("local_signing_account_count"),
            },
        )
    )
    key_package = report.get("key_package") if isinstance(report.get("key_package"), dict) else {}
    availability = str(key_package.get("availability") or "unavailable")
    key_status = {
        "present": ("healthy", "present"),
        "pending": ("degraded", "pending"),
        "degraded": ("degraded", "degraded"),
        "absent": ("degraded", "absent"),
        "unavailable": ("unknown", "worker_unavailable"),
    }.get(availability, ("unknown", "unknown"))
    checks.append(
        diag.check(
            "key_package.availability",
            owner="wn_agent",
            provenance="observed",
            status=key_status[0],
            code=key_status[1],
            value={
                "present": bool(key_package.get("present")),
                "expired": key_package.get("expired"),
                "accepted_fanout_targets": key_package.get("accepted_fanout_targets"),
                "failed_fanout_targets": key_package.get("failed_fanout_targets"),
            },
        )
    )
    checks.append(
        diag.check(
            "authorization.welcomers",
            owner="wn_agent",
            provenance="observed",
            status="healthy" if report.get("allow_any") or (report.get("welcomer_count") or 0) > 0 else "degraded",
            code="allow_any" if report.get("allow_any") else "configured",
            value={
                "welcomer_count": report.get("welcomer_count"),
                "allow_any": bool(report.get("allow_any")),
            },
        )
    )
    relays = report.get("relays") if isinstance(report.get("relays"), dict) else {}
    connected = int(relays.get("connected") or 0)
    configured = int(relays.get("configured") or 0)
    if configured == 0:
        relay_status, relay_code = "unknown", "unknown"
    elif connected == configured:
        relay_status, relay_code = "healthy", "all_connected"
    elif connected == 0:
        relay_status, relay_code = "degraded", "none_connected"
    else:
        relay_status, relay_code = "degraded", "partial"
    checks.append(
        diag.check(
            "relay.health",
            owner="wn_agent",
            provenance="observed",
            status=relay_status,
            code=relay_code,
            value={"configured": configured, "connected": connected, "disconnected": relays.get("disconnected")},
        )
    )
    replay = report.get("replay") if isinstance(report.get("replay"), dict) else {}
    replay_state = str(replay.get("state") or "unknown")
    replay_status = {
        "idle": ("healthy", "idle"),
        "running": ("degraded", "running"),
        "failed": ("degraded", "failed"),
    }.get(replay_state, ("unknown", "unsupported"))
    checks.append(
        diag.check(
            "replay.catch_up",
            owner="wn_agent",
            provenance="observed",
            status=replay_status[0],
            code=replay_status[1],
            value={
                "success_count": replay.get("success_count"),
                "failure_count": replay.get("failure_count"),
                "resync_count": replay.get("resync_count"),
            },
        )
    )
    home = report.get("home") if isinstance(report.get("home"), dict) else {}
    if home_route:
        if home.get("resolved"):
            checks.append(
                diag.check(
                    "home.resolution",
                    owner="wn_agent",
                    provenance="observed",
                    status="healthy",
                    code="resolved",
                    value={"member_count": home.get("member_count"), "is_direct": home.get("is_direct")},
                )
            )
        elif not home.get("worker_available", True):
            checks.append(
                diag.check(
                    "home.resolution",
                    owner="wn_agent",
                    provenance="observed",
                    status="degraded",
                    code="worker_unavailable",
                )
            )
        else:
            checks.append(
                diag.check(
                    "home.resolution",
                    owner="wn_agent",
                    provenance="observed",
                    status="degraded",
                    code="unresolved",
                )
            )
    del account_hex
    return checks


def _plugin_checks(
    live: Optional[dict[str, Any]],
    installed_plugin: Optional[str],
    home_route: Optional[str],
) -> list[dict[str, Any]]:
    if live is None:
        return [
            diag.check(
                "subscription.inbound",
                owner="hermes_plugin",
                provenance="observed",
                status="unknown",
                code="unknown",
            ),
            diag.check(
                "restart.required",
                owner="hermes_plugin",
                provenance="inferred",
                status="unknown",
                code="unknown",
            ),
            diag.check(
                "home.live_agreement",
                owner="hermes_plugin",
                provenance="observed",
                status="unknown",
                code="unknown",
            ),
            diag.check(
                "media.capability",
                owner="hermes_plugin",
                provenance="observed",
                status="unknown",
                code="unknown",
            ),
        ]
    lifecycle = str(live.get("lifecycle") or "unknown")
    sub_status = {
        "established": ("healthy", "established"),
        "awaiting_ack": ("degraded", "awaiting_ack"),
        "starting": ("degraded", "starting"),
        "reconnecting": ("degraded", "reconnecting"),
        "failed": ("degraded", "failed"),
        "stopped": ("unknown", "stopped"),
    }.get(lifecycle, ("unknown", "unknown"))
    checks = [
        diag.check(
            "subscription.inbound",
            owner="hermes_plugin",
            provenance="observed",
            status=sub_status[0],
            code=sub_status[1],
            value={
                "reconnect_count": live.get("reconnect_count"),
                "resync_count": live.get("resync_count"),
                "reconciliation": live.get("reconciliation"),
            },
        )
    ]
    live_version = live.get("plugin_version")
    config_matches = live.get("config_matches")
    if live_version and installed_plugin and live_version != installed_plugin:
        restart_status, restart_code = "degraded", "restart_required"
    elif config_matches is False:
        restart_status, restart_code = "degraded", "restart_required"
    elif config_matches is True and (not installed_plugin or live_version == installed_plugin):
        restart_status, restart_code = "healthy", "matching"
    else:
        restart_status, restart_code = "unknown", "unknown"
    checks.append(
        diag.check(
            "restart.required",
            owner="hermes_plugin",
            provenance="inferred",
            status=restart_status,
            code=restart_code,
        )
    )
    if home_route:
        checks.append(
            diag.check(
                "home.live_agreement",
                owner="hermes_plugin",
                provenance="observed",
                status="healthy" if live.get("home_configured") else "degraded",
                code="matching" if live.get("home_configured") else "mismatch",
            )
        )
    else:
        checks.append(
            diag.check(
                "home.live_agreement",
                owner="hermes_plugin",
                provenance="observed",
                status="unknown",
                code="unknown",
            )
        )
    checks.append(
        diag.check(
            "media.capability",
            owner="hermes_plugin",
            provenance="observed",
            status="healthy" if live.get("media_ready") else "unknown",
            code="ready" if live.get("media_ready") else "unavailable",
        )
    )
    return checks


def _unsupported(check_id: str) -> dict[str, Any]:
    return diag.check(
        check_id,
        owner="wn_agent",
        provenance="observed",
        status="unknown",
        code="unsupported",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Marmot installation doctor")
    parser.add_argument("--home", required=True)
    parser.add_argument("--hermes-home", required=True)
    parser.add_argument("--plugin-dir", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--service-name", required=True)
    parser.add_argument("--launchd-label", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--account-id-hex")
    parser.add_argument("--group-id-hex")
    parser.add_argument("--auth-token")
    parser.add_argument("--auth-token-file")
    parser.add_argument("--install-service", action="store_true", default=True)
    parser.add_argument("--no-install-service", dest="install_service", action="store_false")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = collect(args)
    except Exception:
        report = diag.fatal_helper_report()
        report["checks"][0]["code"] = "collector_error"
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        sys.stdout.write(diag.render_human(report))
    return int(report.get("exit_code") or 1)


if __name__ == "__main__":
    raise SystemExit(main())
