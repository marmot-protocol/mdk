#!/usr/bin/env python3
"""Privacy, fixture, and installer-dispatch tests for the Hermes Marmot doctor."""

from __future__ import annotations

import asyncio
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[4]
HERMES_DIR = REPO_ROOT / "integrations" / "hermes"
PLUGIN_DIR = HERMES_DIR / "marmot"
INSTALLER = REPO_ROOT / "scripts" / "install-hermes-marmot.sh"
CANARIES = (
    "nsec1secretcanary",
    "wss://relay.example.invalid",
    "aa" * 32,
    "/secret/path/token",
    "authorization: Bearer leaked",
)

if str(HERMES_DIR) not in sys.path:
    sys.path.insert(0, str(HERMES_DIR))

from marmot import diagnostics as diag  # noqa: E402
from marmot import doctor  # noqa: E402


def _args(root: Path, **overrides) -> SimpleNamespace:
    values = {
        "home": str(root / "m"),
        "hermes_home": str(root / "h"),
        "plugin_dir": str(root / "p"),
        "socket": str(root / "m" / "dev" / "wn-agent.sock"),
        "prefix": str(root / "prefix"),
        "service_name": "wn-agent-hermes",
        "launchd_label": "org.marmot.wn-agent.hermes",
        "json": True,
        "account_id_hex": None,
        "group_id_hex": None,
        "auth_token": None,
        "auth_token_file": None,
        "install_service": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def _budgeted_tempdir(suffix: str, prefix: str = "h") -> tempfile.TemporaryDirectory:
    tmp = os.environ.get("TMPDIR") or tempfile.gettempdir()
    directory = tempfile.TemporaryDirectory(prefix=prefix, dir=tmp)
    staged = str(Path(directory.name) / suffix.lstrip("/"))
    if len(staged.encode("utf-8")) > diag.UNIX_SOCKET_PATH_MAX:
        directory.cleanup()
        raise AssertionError(
            f"staged unix path exceeds {diag.UNIX_SOCKET_PATH_MAX} bytes under {tmp}"
        )
    return directory


def _short_tempdir(prefix: str = "d-") -> tempfile.TemporaryDirectory:
    return _budgeted_tempdir("h/marmot/diagnostics.sock", prefix=prefix)


def _media_kwargs(
    socket_path,
    extra=None,
    env_values=None,
    fallback_home=None,
) -> dict[str, str]:
    extra = extra or {}
    inbound = diag.resolve_inbound_media_dir(
        extra, socket_path, env_values=env_values, fallback_home=fallback_home
    )
    outbound = diag.resolve_outbound_media_dir(
        extra, socket_path, env_values=env_values, fallback_home=fallback_home
    )
    return {
        "inbound_media_dir": str(inbound),
        "outbound_media_dir": str(outbound),
    }


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _unsafe_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o777)
    return path


class _ConnectorFixture:
    def __init__(
        self,
        socket_path: Path,
        *,
        expected_token: str | None = None,
        report: dict | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.expected_token = expected_token
        self.report = report or {
            "selection": "selected",
            "allow_any": False,
            "welcomer_count": 0,
            "relays": {"configured": 0, "connected": 0, "disconnected": 0},
            "replay": {"state": "idle"},
            "key_package": {"availability": "present"},
        }
        self.requests: list[dict] = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.error: BaseException | None = None

    def start(self) -> None:
        encoded = str(self.socket_path).encode("utf-8")
        if len(encoded) > diag.UNIX_SOCKET_PATH_MAX:
            raise RuntimeError(f"connector fixture path too long ({len(encoded)})")
        self._thread.start()
        if not self._ready.wait(2):
            raise RuntimeError(f"connector fixture failed: {self.error}")
        if self.error:
            raise RuntimeError(f"connector fixture failed: {self.error}")

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(2)

    def _run(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            raw = await reader.readline()
            request = json.loads(raw.decode("utf-8"))
            self.requests.append(request)
            if self.expected_token is not None and request.get("auth_token") != self.expected_token:
                response = {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request.get("id"),
                    "type": "error",
                    "code": "unauthorized",
                    "message": "unauthorized",
                }
            else:
                response = {
                    "marmot_agent_control": "marmot.agent-control.v2",
                    "id": request.get("id"),
                    "type": "diagnostic_status",
                    "report": self.report,
                }
            writer.write(json.dumps(response).encode("utf-8") + b"\n")
            await writer.drain()
            writer.close()

        async def main() -> None:
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
            if self.socket_path.exists():
                self.socket_path.unlink()
            server = await asyncio.start_unix_server(handle, path=str(self.socket_path))
            self._ready.set()
            try:
                while not self._stop.is_set():
                    await asyncio.sleep(0.02)
            finally:
                server.close()
                await server.wait_closed()

        try:
            asyncio.run(main())
        except BaseException as exc:
            self.error = exc
            self._ready.set()


class _PluginFixture:
    def __init__(self, hermes_home: Path, observations: diag.PluginObservations) -> None:
        self.hermes_home = hermes_home
        self.observations = observations
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.error: BaseException | None = None
        self.server: diag.DiagnosticSocketServer | None = None

    def start(self) -> None:
        path = diag.diagnostics_socket_path(self.hermes_home)
        if len(str(path).encode("utf-8")) > diag.UNIX_SOCKET_PATH_MAX:
            raise RuntimeError(f"plugin fixture path too long ({path})")
        self._thread.start()
        if not self._ready.wait(2):
            raise RuntimeError(f"plugin fixture failed: {self.error}")
        if self.error:
            raise RuntimeError(f"plugin fixture failed: {self.error}")
        if self.server is None or getattr(self.server, "_server", None) is None:
            raise RuntimeError(f"plugin fixture socket did not bind: {path}")

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(2)

    def _run(self) -> None:
        async def main() -> None:
            self.server = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(self.hermes_home),
                self.observations,
            )
            await self.server.start()
            self._ready.set()
            try:
                while not self._stop.is_set():
                    await asyncio.sleep(0.02)
            finally:
                await self.server.stop()

        try:
            asyncio.run(main())
        except BaseException as exc:
            self.error = exc
            self._ready.set()


class DoctorReportTests(unittest.TestCase):
    def test_fatal_dominates_and_delivery_is_excluded(self) -> None:
        report = diag.report_object(
            [
                diag.check(
                    "relay.health",
                    owner="wn_agent",
                    provenance="observed",
                    status="degraded",
                    code="partial",
                ),
                diag.check(
                    "account.selection",
                    owner="wn_agent",
                    provenance="observed",
                    status="fatal",
                    code="none",
                ),
                doctor.DELIVERY_CHECK,
            ]
        )
        self.assertEqual(report["status"], "fatal")
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["checks"][-1]["id"], "delivery.probe")
        self.assertEqual(report["checks"][-1]["code"], "not_probed")

    def test_unknown_is_degraded_and_human_matches_json(self) -> None:
        report = diag.report_object(
            [
                diag.check(
                    "service.state",
                    owner="service",
                    provenance="observed",
                    status="unknown",
                    code="unknown",
                )
            ]
        )
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["exit_code"], 1)
        human = diag.render_human(report)
        self.assertIn("service.state: unknown/unknown", human)
        self.assertIn("not delivery", human.lower())

    def test_home_route_accepts_variable_width_and_rejects_garbage(self) -> None:
        self.assertEqual(diag.normalize_home_route("AbCDEF12"), "abcdef12")
        self.assertEqual(diag.normalize_home_route("marmot:" + "11" * 16), "11" * 16)
        self.assertIsNone(diag.normalize_home_route("abc"))
        self.assertIsNone(diag.normalize_home_route("abcd ef"))
        self.assertIsNone(diag.normalize_home_route("zz"))
        self.assertIsNone(diag.normalize_home_route(""))

    def test_manual_service_is_unknown_not_stopped(self) -> None:
        with mock.patch.object(diag, "bounded_run", return_value=None):
            checks = doctor._service_checks("wn-agent-hermes", "org.marmot.wn-agent.hermes", False)
        by_id = {item["id"]: item for item in checks}
        self.assertEqual(by_id["service.manager"]["code"], "not_managed")
        self.assertEqual(by_id["service.state"]["status"], "unknown")

    def test_systemd_and_launchd_states(self) -> None:
        def systemd(_command, **_kwargs):
            return "ActiveState=active\nSubState=running\nType=simple\n"

        with mock.patch.object(diag, "bounded_run", side_effect=systemd):
            checks = doctor._service_checks("wn-agent-hermes", "label", True)
        self.assertEqual(checks[0]["code"], "systemd_user")
        self.assertEqual(checks[1]["code"], "running")

        def launchd(command, **_kwargs):
            if command[0] == "systemctl":
                return None
            return "state = running\npid = 12\n"

        with mock.patch.object(diag, "bounded_run", side_effect=launchd):
            checks = doctor._service_checks("wn-agent-hermes", "label", True)
        self.assertEqual(checks[0]["code"], "launchd")
        self.assertEqual(checks[1]["status"], "healthy")

    def test_collect_missing_paths_is_non_mutating_and_redacts_canaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="d-") as raw:
            root = Path(raw)
            home = root / "m"
            hermes = root / "h"
            plugin = root / "p"
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    extra:\n      group_id_hex: "
                + "11" * 16
                + "\n      socket_path: /secret/path/token\n"
                "      token: nsec1secretcanary\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_ALLOWED_USERS=" + "aa" * 32 + "\n"
                "MARMOT_ALLOW_ALL_USERS=false\n"
                "AUTHORIZATION=Bearer leaked\n"
                "RELAY=wss://relay.example.invalid\n",
            )
            _write(plugin / "plugin.yaml", "version: 0.1.0\n")
            before = _tree_signature(root)
            args = _args(root, group_id_hex="11" * 16)
            with mock.patch.object(diag, "bounded_run", return_value=None):
                report = doctor.collect(args)
            after = _tree_signature(root)
            self.assertEqual(before, after)
            encoded = json.dumps(report) + diag.render_human(report)
            for canary in CANARIES:
                self.assertNotIn(canary, encoded)
            by_id = {item["id"]: item for item in report["checks"]}
            self.assertEqual(by_id["delivery.probe"]["code"], "not_probed")
            self.assertEqual(by_id["home.syntax"]["status"], "healthy")
            self.assertIn(by_id["socket.control"]["code"], {"missing", "not_created"})
            self.assertEqual(report["schema_version"], 1)

    def test_unsafe_socket_and_symlink_are_fatal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="du-") as raw:
            root = Path(raw)
            home = root / "marmot-home"
            home.mkdir(mode=0o700)
            socket = home / "dev" / "wn-agent.sock"
            socket.parent.mkdir(mode=0o700)
            socket.write_text("not-a-socket", encoding="utf-8")
            os.chmod(socket, 0o666)
            check = doctor._socket_check(socket)
            self.assertEqual(check["status"], "fatal")
            link = home / "dev" / "link.sock"
            link.symlink_to(socket)
            linked = doctor._socket_check(link)
            self.assertEqual(linked["code"], "symlink")

    def test_odd_home_override_is_degraded(self) -> None:
        extra = {"group_id_hex": "abc"}
        route = doctor._configured_home_route(extra, "abc")
        self.assertIsNone(route)

    def test_inbound_filter_is_not_home_fallback(self) -> None:
        extra = {"group": "aa" * 16, "group_id_hex": "bb" * 16, "home_channel": None}
        self.assertIsNone(doctor._configured_home_route(extra, None))

    def test_main_preserves_healthy_zero_exit(self) -> None:
        argv = [
            "--home",
            "/tmp/home",
            "--hermes-home",
            "/tmp/hermes",
            "--plugin-dir",
            "/tmp/plugin",
            "--socket",
            "/tmp/sock",
            "--prefix",
            "/tmp/prefix",
            "--service-name",
            "wn-agent-hermes",
            "--launchd-label",
            "org.marmot.wn-agent.hermes",
            "--json",
        ]
        healthy = diag.report_object(
            [
                diag.check(
                    "authorization.config",
                    owner="hermes_config",
                    provenance="observed",
                    status="healthy",
                    code="present",
                )
            ]
        )
        degraded = diag.report_object(
            [
                diag.check(
                    "relay.health",
                    owner="wn_agent",
                    provenance="observed",
                    status="degraded",
                    code="partial",
                )
            ]
        )
        fatal = diag.report_object(
            [
                diag.check(
                    "account.selection",
                    owner="wn_agent",
                    provenance="observed",
                    status="fatal",
                    code="none",
                )
            ]
        )
        self.assertEqual(healthy["exit_code"], 0)
        stdout = io.StringIO()
        with mock.patch.object(doctor, "collect", return_value=healthy), mock.patch.object(sys, "stdout", stdout):
            self.assertEqual(doctor.main(argv), 0)
        self.assertIn('"exit_code":0', stdout.getvalue().replace(" ", ""))
        with mock.patch.object(doctor, "collect", return_value=degraded), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(doctor.main(argv), 1)
        with mock.patch.object(doctor, "collect", return_value=fatal), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(doctor.main(argv), 2)

    def test_main_process_exits_match_report(self) -> None:
        script = (
            "import json, sys\n"
            "from unittest import mock\n"
            f"sys.path.insert(0, {str(HERMES_DIR)!r})\n"
            "from marmot import diagnostics as diag\n"
            "from marmot import doctor\n"
            "argv = json.loads(sys.argv[1])\n"
            "status = sys.argv[2]\n"
            "report = diag.report_object([\n"
            "    diag.check('authorization.config', owner='hermes_config', provenance='observed', status=status,\n"
            "               code='present' if status == 'healthy' else status)\n"
            "])\n"
            "with mock.patch.object(doctor, 'collect', return_value=report):\n"
            "    raise SystemExit(doctor.main(argv))\n"
        )
        argv = [
            "--home",
            "/tmp/home",
            "--hermes-home",
            "/tmp/hermes",
            "--plugin-dir",
            "/tmp/plugin",
            "--socket",
            "/tmp/sock",
            "--prefix",
            "/tmp/prefix",
            "--service-name",
            "wn-agent-hermes",
            "--launchd-label",
            "org.marmot.wn-agent.hermes",
            "--json",
        ]
        for status, expected in (("healthy", 0), ("degraded", 1), ("fatal", 2)):
            completed = subprocess.run(
                [sys.executable, "-c", script, json.dumps(argv), status],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(completed.returncode, expected, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["exit_code"], expected)

    def test_systemd_loadstate_not_found_is_unknown(self) -> None:
        def systemd(_command, **_kwargs):
            return "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"

        with mock.patch.object(diag, "bounded_run", side_effect=systemd):
            managed = doctor._service_checks("wn-agent-hermes", "label", True)
            manual = doctor._service_checks("wn-agent-hermes", "label", False)
        self.assertEqual(managed[1]["status"], "unknown")
        self.assertEqual(managed[1]["code"], "not_managed")
        self.assertEqual(manual[1]["status"], "unknown")
        self.assertEqual(manual[1]["code"], "not_managed")

    def test_systemd_masked_and_loaded_inactive(self) -> None:
        def masked(_command, **_kwargs):
            return "LoadState=masked\nActiveState=inactive\n"

        def loaded(_command, **_kwargs):
            return "LoadState=loaded\nActiveState=inactive\n"

        def invalid(_command, **_kwargs):
            return "LoadState=bad-setting\nActiveState=inactive\n"

        with mock.patch.object(diag, "bounded_run", side_effect=masked):
            checks = doctor._service_checks("wn-agent-hermes", "label", True)
        self.assertEqual(checks[1]["status"], "fatal")
        self.assertEqual(checks[1]["code"], "masked")
        with mock.patch.object(diag, "bounded_run", side_effect=loaded):
            checks = doctor._service_checks("wn-agent-hermes", "label", True)
        self.assertEqual(checks[1]["status"], "fatal")
        self.assertEqual(checks[1]["code"], "stopped")
        with mock.patch.object(diag, "bounded_run", side_effect=invalid):
            checks = doctor._service_checks("wn-agent-hermes", "label", True)
        self.assertEqual(checks[1]["status"], "fatal")
        self.assertEqual(checks[1]["code"], "invalid")

    def test_home_uses_platform_channel_not_inbound_filter(self) -> None:
        home_b = "bb" * 16
        filter_a = "aa" * 16
        extra = {"group_id_hex": filter_a, "group": filter_a}
        self.assertIsNone(doctor._configured_home_route(extra, None))
        self.assertEqual(
            doctor._configured_home_route(extra, None, home_channel=home_b, home_platform="marmot"),
            home_b,
        )
        route, error = diag.resolve_home_route(
            extra,
            home_channel=home_b,
            home_platform="telegram",
        )
        self.assertIsNone(route)
        self.assertEqual(error, "wrong_platform")
        self.assertEqual(diag.normalize_home_route("11" * 8), "11" * 8)

    def test_effective_config_merges_legacy_plugin_and_env(self) -> None:
        config = {
            "platforms": {
                "marmot": {
                    "home_channel": {"platform": "marmot", "chat_id": "cc" * 16},
                    "extra": {"socket_path": "/legacy/socket", "account_id_hex": "11" * 32},
                }
            },
            "plugins": {
                "entries": {
                    "marmot": {
                        "settings": {
                            "socket_path": "/plugin/socket",
                            "account_id_hex": "22" * 32,
                            "home_channel": "dd" * 16,
                        }
                    }
                }
            },
        }
        merged = diag.merge_hermes_marmot_config(config)
        self.assertEqual(merged["extra"]["socket_path"], "/legacy/socket")
        self.assertEqual(merged["extra"]["account_id_hex"], "11" * 32)
        self.assertEqual(merged["home_channel"], "cc" * 16)
        with mock.patch.dict(os.environ, {"MARMOT_ACCOUNT_ID_HEX": "33" * 32, "MARMOT_AGENT_SOCKET": "/env/socket"}):
            account, mode = diag.resolve_account_id(merged["extra"])
            socket = diag.resolve_socket_path(merged["extra"])
        self.assertEqual(account, "33" * 32)
        self.assertEqual(mode, "explicit")
        self.assertEqual(str(socket), "/env/socket")
        account, mode = diag.resolve_account_id({"account_id_hex": "not-an-account"})
        self.assertIsNone(account)
        self.assertEqual(mode, "invalid")

    def test_collect_uses_configured_socket_token_and_account(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dc-") as raw:
            root = Path(raw)
            home = root / "m"
            hermes = root / "h"
            plugin = root / "p"
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            token_file = hermes / "token"
            _write(token_file, "nsec1secretcanary\n")
            custom_socket = root / "custom.sock"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + "11" * 16 + "\n    extra:\n"
                "      socket_path: " + str(custom_socket) + "\n"
                "      account_id_hex: " + "22" * 32 + "\n"
                "      auth_token_file: " + str(token_file) + "\n"
                "plugins:\n  entries:\n    marmot:\n      settings:\n"
                "        group_id_hex: " + "aa" * 16 + "\n",
            )
            _write(hermes / ".env", "MARMOT_ALLOW_ALL_USERS=false\n")
            captured: dict[str, object] = {}

            def fake_report(socket_path, account_hex, home_route, auth_token):
                captured["socket"] = str(socket_path)
                captured["account"] = account_hex
                captured["home"] = home_route
                captured["token"] = auth_token
                return {"unsupported": True}

            args = _args(root)
            with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                doctor, "_connector_report", side_effect=fake_report
            ):
                report = doctor.collect(args)
            self.assertEqual(captured["socket"], str(custom_socket))
            self.assertEqual(captured["account"], "22" * 32)
            self.assertEqual(captured["home"], "11" * 16)
            self.assertEqual(captured["token"], "nsec1secretcanary")
            encoded = json.dumps(report) + diag.render_human(report)
            for canary in CANARIES:
                self.assertNotIn(canary, encoded)
            self.assertNotIn(str(custom_socket), encoded)
            by_id = {item["id"]: item for item in report["checks"]}
            self.assertEqual(by_id["home.syntax"]["status"], "healthy")
            self.assertEqual(by_id["home.configured_route"]["code"], "present")

    def test_home_filter_mismatch_and_absent_home(self) -> None:
        live = {
            "lifecycle": "established",
            "reconciliation": "succeeded",
            "config_matches": True,
            "home_configured": True,
            "home_matches": False,
            "media_ready": True,
            "reconnect_count": 0,
            "resync_count": 0,
            "recovery_count": 1,
            "last_disconnect_reason": "clean_eof",
        }
        checks = doctor._plugin_checks(live, "0.1.0", "bb" * 16)
        by_id = {item["id"]: item for item in checks}
        self.assertEqual(by_id["home.live_agreement"]["code"], "mismatch")
        self.assertEqual(by_id["home.live_agreement"]["status"], "degraded")
        self.assertEqual(by_id["subscription.inbound"]["status"], "healthy")
        self.assertEqual(by_id["subscription.inbound"]["value"]["recovery_count"], 1)
        self.assertEqual(by_id["subscription.inbound"]["value"]["last_disconnect_reason"], "clean_eof")
        absent = doctor._plugin_checks(
            {**live, "home_matches": None, "home_configured": False},
            "0.1.0",
            None,
        )
        self.assertEqual({item["id"]: item for item in absent}["home.live_agreement"]["code"], "unknown")

    def test_reconciliation_failure_degrades_then_recovers(self) -> None:
        failed = doctor._plugin_checks(
            {
                "lifecycle": "established",
                "reconciliation": "failed",
                "config_matches": True,
                "home_matches": True,
                "media_ready": True,
            },
            "0.1.0",
            "11" * 16,
        )
        self.assertEqual({item["id"]: item for item in failed}["subscription.inbound"]["status"], "degraded")
        self.assertEqual({item["id"]: item for item in failed}["subscription.inbound"]["code"], "failed")
        pending = doctor._plugin_checks(
            {
                "lifecycle": "established",
                "reconciliation": "pending",
                "config_matches": True,
                "home_matches": True,
                "media_ready": True,
            },
            "0.1.0",
            "11" * 16,
        )
        self.assertEqual({item["id"]: item for item in pending}["subscription.inbound"]["code"], "pending")
        recovered = doctor._plugin_checks(
            {
                "lifecycle": "established",
                "reconciliation": "succeeded",
                "config_matches": True,
                "home_matches": True,
                "media_ready": True,
            },
            "0.1.0",
            "11" * 16,
        )
        self.assertEqual({item["id"]: item for item in recovered}["subscription.inbound"]["status"], "healthy")

    def test_old_connector_socket_closed_is_unsupported(self) -> None:
        checks = doctor._connector_checks({"error_code": "socket_closed"}, None, None, None)
        self.assertTrue(all(item["code"] == "unsupported" for item in checks))
        self.assertTrue(all(item["status"] == "unknown" for item in checks))

    def test_welcomers_empty_and_safe_relay_counts(self) -> None:
        checks = doctor._connector_checks(
            {
                "type": "diagnostic_status",
                "report": {
                    "selection": "selected",
                    "allow_any": False,
                    "welcomer_count": 0,
                    "relays": {"configured": "bad", "connected": None},
                    "replay": {"state": "idle"},
                    "key_package": {"availability": "present"},
                },
            },
            None,
            None,
            None,
        )
        by_id = {item["id"]: item for item in checks}
        self.assertEqual(by_id["authorization.welcomers"]["code"], "empty")
        self.assertEqual(by_id["relay.health"]["code"], "unknown")
        self.assertEqual(by_id["relay.health"]["value"]["configured"], 0)

    def test_fingerprints_hash_identities_and_ignore_false_env(self) -> None:
        media = diag.media_fingerprint_value()
        first = diag.nonsecret_config_fields(
            senders=["aa" * 32],
            allow_all=False,
            welcomers=["bb" * 32],
            account_id_hex="11" * 32,
            socket_path="/tmp/one.sock",
            home_route="cc" * 16,
            media=media,
        )
        replaced = diag.nonsecret_config_fields(
            senders=["aa" * 32],
            allow_all=False,
            welcomers=["bb" * 32],
            account_id_hex="22" * 32,
            socket_path="/tmp/two.sock",
            home_route="cc" * 16,
            media=media,
        )
        self.assertNotEqual(diag.config_fingerprint(first), diag.config_fingerprint(replaced))
        self.assertNotIn("11" * 32, json.dumps(first))
        self.assertNotIn("/tmp/one.sock", json.dumps(first))
        self.assertFalse(diag.parse_config_bool("false"))
        self.assertFalse(diag.parse_config_bool("0"))
        self.assertNotIn("host_outbound_dispatch", diag.media_fingerprint_value())
        with mock.patch.object(diag, "host_outbound_dispatch_status", return_value=None):
            unknown = diag.media_capability_status()
        self.assertIsNone(unknown["host_outbound_dispatch"])
        self.assertEqual(unknown["inbound"], list(diag.INBOUND_MEDIA_KINDS))

    def test_recovery_counts_across_awaiting_ack(self) -> None:
        observations = diag.PluginObservations()
        observations.mark("starting")
        observations.mark("awaiting_ack")
        observations.mark("established")
        self.assertEqual(observations.recovery_count, 0)
        observations.mark("reconnecting", reason="clean_eof")
        observations.mark("awaiting_ack")
        observations.mark("established")
        self.assertEqual(observations.reconnect_count, 1)
        self.assertEqual(observations.recovery_count, 1)
        self.assertEqual(observations.last_disconnect_reason, "clean_eof")

    def test_home_channel_env_and_dotenv_precedence(self) -> None:
        platform_home = "aa" * 16
        plugin_home = "bb" * 16
        env_home = "cc" * 16
        dotenv_home = "dd" * 16
        config = {
            "platforms": {
                "marmot": {
                    "home_channel": {"platform": "marmot", "chat_id": platform_home},
                    "extra": {"socket_path": "/tmp/yaml.sock"},
                }
            },
            "plugins": {"entries": {"marmot": {"settings": {"home_channel": plugin_home}}}},
        }
        cases = (
            ({"MARMOT_AGENT_SOCKET": "/tmp/env.sock", "MARMOT_HOME_CHANNEL": env_home}, {}, env_home),
            (
                {"MARMOT_AGENT_SOCKET": "/tmp/env.sock", "MARMOT_HOME_CHANNEL": env_home},
                {"MARMOT_HOME_CHANNEL": dotenv_home, "MARMOT_AGENT_SOCKET": "/tmp/dot.sock"},
                dotenv_home,
            ),
            ({}, {"MARMOT_HOME_CHANNEL": dotenv_home, "MARMOT_AGENT_SOCKET": "/tmp/dot.sock"}, dotenv_home),
            ({"MARMOT_HOME_CHANNEL": env_home}, {}, plugin_home),
            ({}, {}, plugin_home),
        )
        for process_env, dotenv_values, expected in cases:
            with self.subTest(process_env=process_env, dotenv=bool(dotenv_values)):
                environ = {key: "" for key in ("MARMOT_AGENT_SOCKET", "MARMOT_HOME", "MARMOT_HOME_CHANNEL")}
                environ.update(process_env)
                projected = diag.project_effective_env(dotenv_values, environ=environ)
                merged = diag.merge_hermes_marmot_config(config)
                seed = diag.env_enablement_seed(
                    diag.plugin_settings_from_config(config),
                    env_values=projected,
                )
                effective = diag.apply_enablement_seed(merged, seed)
                route, error = diag.resolve_home_route(
                    effective["extra"],
                    home_channel=effective["home_channel"],
                    home_platform=effective["home_platform"],
                    env_values=projected,
                )
                self.assertEqual(route, expected)
                self.assertIsNone(error)
        yaml_only = {
            "platforms": {
                "marmot": {
                    "home_channel": {"platform": "marmot", "chat_id": platform_home},
                    "extra": {"socket_path": "/tmp/yaml.sock"},
                }
            }
        }
        projected = diag.project_effective_env({}, environ={"MARMOT_HOME_CHANNEL": env_home})
        merged = diag.merge_hermes_marmot_config(yaml_only)
        effective = diag.apply_enablement_seed(
            merged,
            diag.env_enablement_seed(diag.plugin_settings_from_config(yaml_only), env_values=projected),
        )
        route, error = diag.resolve_home_route(
            effective["extra"],
            home_channel=effective["home_channel"],
            home_platform=effective["home_platform"],
            env_values=projected,
        )
        self.assertEqual(route, platform_home)
        self.assertIsNone(error)

    def test_auth_token_inline_beats_file_argument(self) -> None:
        with _short_tempdir("at-") as raw:
            token_file = Path(raw) / "file.token"
            _write(token_file, "file-token-canary\n")
            extra = {"auth_token_file": str(token_file)}
            with mock.patch.dict(
                os.environ,
                {
                    "MARMOT_AGENT_AUTH_TOKEN": "inline-token-canary",
                    "MARMOT_AGENT_AUTH_TOKEN_FILE": str(token_file),
                },
                clear=False,
            ):
                token, error = diag.resolve_auth_token(extra, token_file=str(token_file))
            self.assertEqual(token, "inline-token-canary")
            self.assertIsNone(error)
            token, error = diag.resolve_auth_token({"auth_token": "yaml-inline"}, token_file=str(token_file))
            self.assertEqual(token, "yaml-inline")

    def test_welcomer_alias_empty_and_env_equivalence(self) -> None:
        cases = (
            ({"welcomer_allowlist": ["aa" * 32]}, ["aa" * 32]),
            ({"welcomerAllowlist": "bb" * 32}, ["bb" * 32]),
            ({"dm_allow_from": ["cc" * 32]}, ["cc" * 32]),
            ({"dmAllowFrom": "dd" * 32 + "," + "ee" * 32}, ["dd" * 32, "ee" * 32]),
            ({"welcomer_allowlist": []}, []),
            ({"dm_allow_from": ""}, []),
        )
        for extra, expected in cases:
            with self.subTest(extra=extra):
                with mock.patch.dict(
                    os.environ,
                    {"MARMOT_WELCOMER_ALLOWLIST": "ff" * 32, "MARMOT_DM_ALLOW_FROM": "gg" * 32},
                    clear=False,
                ):
                    self.assertEqual(diag.resolve_welcomers(extra), expected)
        with mock.patch.dict(os.environ, {"MARMOT_WELCOMER_ALLOWLIST": "hh" * 32}, clear=False):
            self.assertEqual(diag.resolve_welcomers({}), ["hh" * 32])
        with mock.patch.dict(os.environ, {"MARMOT_WELCOMER_ALLOWLIST": "", "MARMOT_DM_ALLOW_FROM": ""}, clear=False):
            os.environ.pop("MARMOT_WELCOMER_ALLOWLIST", None)
            os.environ.pop("MARMOT_DM_ALLOW_FROM", None)
            self.assertEqual(
                diag.resolve_welcomers({}, env_values={"MARMOT_DM_ALLOW_FROM": "ii" * 32}),
                ["ii" * 32],
            )
        with mock.patch.dict(os.environ, {"MARMOT_WELCOMER_ALLOWLIST": "jj" * 32}, clear=False):
            self.assertEqual(
                diag.resolve_welcomers({"welcomer_allowlist": []}, env_values={"MARMOT_WELCOMER_ALLOWLIST": "kk" * 32}),
                [],
            )

    def test_collect_dotenv_connector_and_home_without_yaml(self) -> None:
        with _short_tempdir("de-") as raw:
            root = Path(raw)
            args = _args(root)
            home = Path(args.home)
            hermes = Path(args.hermes_home)
            plugin = Path(args.plugin_dir)
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            token_file = hermes / "t"
            _write(token_file, "dotenv-file-token\n")
            custom_socket = root / "c.sock"
            dotenv_home = "11" * 16
            dotenv_account = "22" * 32
            _write(
                hermes / ".env",
                "MARMOT_AGENT_SOCKET=" + str(custom_socket) + "\n"
                "MARMOT_ACCOUNT_ID_HEX=" + dotenv_account + "\n"
                "MARMOT_AGENT_AUTH_TOKEN=dotenv-inline-token\n"
                "MARMOT_AGENT_AUTH_TOKEN_FILE=" + str(token_file) + "\n"
                "MARMOT_HOME_CHANNEL=" + dotenv_home + "\n"
                "AUTHORIZATION=Bearer leaked\n",
            )
            captured: dict[str, object] = {}

            def fake_report(socket_path, account_hex, home_route, auth_token):
                captured["socket"] = str(socket_path)
                captured["account"] = account_hex
                captured["home"] = home_route
                captured["token"] = auth_token
                return {"unsupported": True}

            env_clear = {
                "MARMOT_AGENT_SOCKET": "",
                "MARMOT_ACCOUNT_ID_HEX": "",
                "MARMOT_AGENT_AUTH_TOKEN": "",
                "MARMOT_AGENT_AUTH_TOKEN_FILE": "",
                "MARMOT_HOME_CHANNEL": "",
            }
            with mock.patch.dict(os.environ, env_clear, clear=False):
                for key in list(env_clear):
                    os.environ.pop(key, None)
                with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                    doctor, "_connector_report", side_effect=fake_report
                ):
                    report = doctor.collect(args)
            self.assertEqual(captured["socket"], str(custom_socket))
            self.assertEqual(captured["account"], dotenv_account)
            self.assertEqual(captured["home"], dotenv_home)
            self.assertEqual(captured["token"], "dotenv-inline-token")
            encoded = json.dumps(report) + diag.render_human(report)
            self.assertNotIn("dotenv-inline-token", encoded)
            self.assertNotIn("dotenv-file-token", encoded)
            self.assertNotIn(str(custom_socket), encoded)
            by_id = {item["id"]: item for item in report["checks"]}
            self.assertEqual(by_id["home.syntax"]["status"], "healthy")
            self.assertEqual(by_id["home.configured_route"]["code"], "present")

    def test_collect_conflicting_yaml_dotenv_and_process_matches_adapter(self) -> None:
        yaml_home = "aa" * 16
        dotenv_home = "bb" * 16
        process_home = "cc" * 16
        yaml_account = "11" * 32
        dotenv_account = "22" * 32
        process_account = "33" * 32
        with _short_tempdir("cx-") as raw:
            root = Path(raw)
            args = _args(root)
            home = Path(args.home)
            hermes = Path(args.hermes_home)
            plugin = Path(args.plugin_dir)
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            yaml_socket = root / "y.sock"
            dotenv_socket = root / "d.sock"
            process_socket = root / "e.sock"
            yaml_token_file = hermes / "yaml.token"
            dotenv_token_file = hermes / "dot.token"
            process_token_file = hermes / "env.token"
            _write(yaml_token_file, "yaml-file-token\n")
            _write(dotenv_token_file, "dotenv-file-token\n")
            _write(process_token_file, "process-file-token\n")
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + yaml_home + "\n    extra:\n"
                "      socket_path: " + str(yaml_socket) + "\n"
                "      account_id_hex: " + yaml_account + "\n"
                "      auth_token: yaml-inline-token\n"
                "      auth_token_file: " + str(yaml_token_file) + "\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_AGENT_SOCKET=" + str(dotenv_socket) + "\n"
                "MARMOT_ACCOUNT_ID_HEX=" + dotenv_account + "\n"
                "MARMOT_HOME_CHANNEL=" + dotenv_home + "\n"
                "MARMOT_AGENT_AUTH_TOKEN=dotenv-inline-token\n"
                "MARMOT_AGENT_AUTH_TOKEN_FILE=" + str(dotenv_token_file) + "\n",
            )
            captured: dict[str, object] = {}

            def fake_report(socket_path, account_hex, home_route, auth_token):
                captured["socket"] = str(socket_path)
                captured["account"] = account_hex
                captured["home"] = home_route
                captured["token"] = auth_token
                return {"unsupported": True}

            process_env = {
                "MARMOT_AGENT_SOCKET": str(process_socket),
                "MARMOT_ACCOUNT_ID_HEX": process_account,
                "MARMOT_HOME_CHANNEL": process_home,
                "MARMOT_AGENT_AUTH_TOKEN": "process-inline-token",
                "MARMOT_AGENT_AUTH_TOKEN_FILE": str(process_token_file),
                "MARMOT_HOME": "",
            }
            with mock.patch.dict(os.environ, process_env, clear=False), mock.patch.object(
                diag, "bounded_run", return_value=None
            ), mock.patch.object(doctor, "_connector_report", side_effect=fake_report):
                report = doctor.collect(args)
                projected = diag.project_effective_env(diag.parse_env_safely(hermes / ".env").values)
                extra = {
                    "socket_path": str(yaml_socket),
                    "account_id_hex": yaml_account,
                    "auth_token": "yaml-inline-token",
                    "auth_token_file": str(yaml_token_file),
                }
                expected_socket = diag.resolve_socket_path(extra, env_values=projected)
                expected_account, _mode = diag.resolve_account_id(extra, env_values=projected)
                expected_token, token_error = diag.resolve_auth_token(extra, env_values=projected)
                expected_seed = diag.env_enablement_seed(env_values=projected)
            self.assertEqual(captured["socket"], str(dotenv_socket))
            self.assertEqual(captured["account"], dotenv_account)
            self.assertEqual(captured["home"], dotenv_home)
            self.assertEqual(captured["token"], "dotenv-inline-token")
            self.assertEqual(str(expected_socket), str(dotenv_socket))
            self.assertEqual(expected_account, dotenv_account)
            self.assertEqual(expected_token, "dotenv-inline-token")
            self.assertIsNone(token_error)
            self.assertEqual(expected_seed["home_channel"]["chat_id"], dotenv_home)
            encoded = json.dumps(report) + diag.render_human(report)
            self.assertNotIn("dotenv-inline-token", encoded)
            self.assertNotIn("yaml-inline-token", encoded)
            self.assertNotIn("process-inline-token", encoded)
            self.assertNotIn(str(dotenv_socket), encoded)
            self.assertNotIn(dotenv_account, encoded)

    def test_local_token_file_errors_are_not_unauthorized(self) -> None:
        with _short_tempdir("tf-") as raw:
            root = Path(raw)
            args = _args(root)
            Path(args.home).mkdir(mode=0o700)
            Path(args.hermes_home).mkdir(mode=0o700)
            Path(args.plugin_dir).mkdir(mode=0o700)
            missing = Path(args.hermes_home) / "missing.token"
            empty = Path(args.hermes_home) / "empty.token"
            _write(empty, "\n")
            with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.dict(
                os.environ, {"MARMOT_AGENT_AUTH_TOKEN_FILE": str(missing), "MARMOT_AGENT_AUTH_TOKEN": ""}, clear=False
            ):
                os.environ.pop("MARMOT_AGENT_AUTH_TOKEN", None)
                missing_report = doctor.collect(args)
            missing_ids = {item["id"]: item for item in missing_report["checks"]}
            self.assertEqual(missing_ids["account.selection"]["owner"], "hermes_config")
            self.assertEqual(missing_ids["account.selection"]["code"], "unreadable")
            with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.dict(
                os.environ, {"MARMOT_AGENT_AUTH_TOKEN_FILE": str(empty), "MARMOT_AGENT_AUTH_TOKEN": ""}, clear=False
            ):
                os.environ.pop("MARMOT_AGENT_AUTH_TOKEN", None)
                empty_report = doctor.collect(args)
            empty_ids = {item["id"]: item for item in empty_report["checks"]}
            self.assertEqual(empty_ids["account.selection"]["owner"], "hermes_config")
            self.assertEqual(empty_ids["account.selection"]["code"], "empty")

    def test_collect_live_home_env_agrees_and_detects_mismatch(self) -> None:
        env_home = "33" * 16
        other_home = "44" * 16
        with _short_tempdir("lh-") as raw:
            root = Path(raw)
            args = _args(root)
            home = Path(args.home)
            hermes = Path(args.hermes_home)
            plugin = Path(args.plugin_dir)
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            _write(plugin / "plugin.yaml", "version: 0.1.0\n")
            connector_socket = root / "c.sock"
            observations = diag.PluginObservations()
            observations.mark("established")
            observations.reconciliation = "succeeded"
            observations.plugin_version = "0.1.0"
            observations.loaded_home_digest = diag.identity_digest(env_home)
            fields = diag.nonsecret_config_fields(
                senders=[],
                allow_all=False,
                welcomers=[],
                account_id_hex=None,
                socket_path=str(connector_socket),
                home_route=env_home,
                **_media_kwargs(connector_socket, fallback_home=home),
            )
            observations.loaded_fingerprint = diag.config_fingerprint(fields)
            connector = _ConnectorFixture(connector_socket)
            plugin_server = _PluginFixture(hermes, observations)
            connector.start()
            plugin_server.start()
            try:
                env = {
                    "MARMOT_AGENT_SOCKET": str(connector_socket),
                    "MARMOT_HOME_CHANNEL": env_home,
                    "MARMOT_ALLOWED_USERS": "",
                    "MARMOT_ALLOW_ALL_USERS": "",
                    "MARMOT_WELCOMER_ALLOWLIST": "",
                    "MARMOT_DM_ALLOW_FROM": "",
                    "MARMOT_ACCOUNT_ID_HEX": "",
                    "MARMOT_AGENT_AUTH_TOKEN": "",
                }
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    first = doctor.collect(_args(root, socket=str(connector_socket)))
                self.assertTrue(connector.requests)
                self.assertEqual(connector.requests[0].get("home_group_id_hex"), env_home)
                by_id = {item["id"]: item for item in first["checks"]}
                self.assertEqual(by_id["home.syntax"]["status"], "healthy")
                self.assertEqual(by_id["home.live_agreement"]["code"], "matching")
                self.assertEqual(by_id["restart.required"]["code"], "matching")
                observations.loaded_home_digest = diag.identity_digest(other_home)
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    mismatched = doctor.collect(_args(root, socket=str(connector_socket)))
                mismatch_ids = {item["id"]: item for item in mismatched["checks"]}
                self.assertEqual(mismatch_ids["home.live_agreement"]["code"], "mismatch")
                observations.loaded_home_digest = diag.identity_digest(env_home)
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    recovered = doctor.collect(_args(root, socket=str(connector_socket)))
                self.assertEqual(
                    {item["id"]: item for item in recovered["checks"]}["home.live_agreement"]["code"],
                    "matching",
                )
            finally:
                plugin_server.stop()
                connector.stop()

    def test_collect_live_dotenv_overrides_yaml_and_recovers_after_change(self) -> None:
        yaml_home = "66" * 16
        dotenv_home = "77" * 16
        other_home = "88" * 16
        yaml_account = "11" * 32
        dotenv_account = "22" * 32
        with _short_tempdir("ld-") as raw:
            root = Path(raw)
            args = _args(root)
            home = Path(args.home)
            hermes = Path(args.hermes_home)
            plugin = Path(args.plugin_dir)
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            _write(plugin / "plugin.yaml", "version: 0.1.0\n")
            yaml_socket = root / "y.sock"
            dotenv_socket = root / "d.sock"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + yaml_home + "\n    extra:\n"
                "      socket_path: " + str(yaml_socket) + "\n"
                "      account_id_hex: " + yaml_account + "\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_AGENT_SOCKET=" + str(dotenv_socket) + "\n"
                "MARMOT_ACCOUNT_ID_HEX=" + dotenv_account + "\n"
                "MARMOT_HOME_CHANNEL=" + dotenv_home + "\n",
            )
            observations = diag.PluginObservations()
            observations.mark("established")
            observations.reconciliation = "succeeded"
            observations.plugin_version = "0.1.0"
            observations.loaded_home_digest = diag.identity_digest(dotenv_home)
            fields = diag.nonsecret_config_fields(
                senders=[],
                allow_all=False,
                welcomers=[],
                account_id_hex=dotenv_account,
                socket_path=str(dotenv_socket),
                home_route=dotenv_home,
                **_media_kwargs(dotenv_socket, fallback_home=home),
            )
            observations.loaded_fingerprint = diag.config_fingerprint(fields)
            connector = _ConnectorFixture(dotenv_socket)
            plugin_server = _PluginFixture(hermes, observations)
            connector.start()
            plugin_server.start()
            try:
                with mock.patch.object(diag, "bounded_run", return_value=None):
                    first = doctor.collect(args)
                self.assertTrue(connector.requests)
                self.assertEqual(connector.requests[0].get("home_group_id_hex"), dotenv_home)
                self.assertEqual(connector.requests[0].get("account_id_hex"), dotenv_account)
                by_id = {item["id"]: item for item in first["checks"]}
                self.assertEqual(by_id["home.live_agreement"]["code"], "matching")
                self.assertEqual(by_id["restart.required"]["code"], "matching")
                observations.loaded_home_digest = diag.identity_digest(other_home)
                with mock.patch.object(diag, "bounded_run", return_value=None):
                    mismatched = doctor.collect(args)
                self.assertEqual(
                    {item["id"]: item for item in mismatched["checks"]}["home.live_agreement"]["code"],
                    "mismatch",
                )
                observations.loaded_home_digest = diag.identity_digest(dotenv_home)
                observations.loaded_fingerprint = diag.config_fingerprint(fields)
                with mock.patch.object(diag, "bounded_run", return_value=None):
                    recovered = doctor.collect(args)
                recovered_ids = {item["id"]: item for item in recovered["checks"]}
                self.assertEqual(recovered_ids["home.live_agreement"]["code"], "matching")
                self.assertEqual(recovered_ids["restart.required"]["code"], "matching")
            finally:
                plugin_server.stop()
                connector.stop()

    def test_collect_live_welcomer_alias_and_identity_replacement(self) -> None:
        home_route = "55" * 16
        first_id = "aa" * 32
        second_id = "bb" * 32
        with _short_tempdir("lw-") as raw:
            root = Path(raw)
            args = _args(root)
            home = Path(args.home)
            hermes = Path(args.hermes_home)
            plugin = Path(args.plugin_dir)
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            plugin.mkdir(mode=0o700)
            _write(plugin / "plugin.yaml", "version: 0.1.0\n")
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + home_route + "\n    extra:\n"
                "      dm_allow_from: " + first_id + "\n",
            )
            observations = diag.PluginObservations()
            observations.mark("established")
            observations.reconciliation = "succeeded"
            observations.plugin_version = "0.1.0"
            alias_fields = diag.nonsecret_config_fields(
                senders=[],
                allow_all=False,
                welcomers=diag.resolve_welcomers({"dm_allow_from": [first_id]}),
                account_id_hex=None,
                socket_path=str(_args(root).socket),
                home_route=home_route,
                **_media_kwargs(_args(root).socket, fallback_home=home),
            )
            observations.loaded_fingerprint = diag.config_fingerprint(alias_fields)
            observations.loaded_home_digest = diag.identity_digest(home_route)
            plugin_server = _PluginFixture(hermes, observations)
            plugin_server.start()
            try:
                with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                    doctor, "_connector_report", return_value={"unsupported": True}
                ):
                    matching = doctor.collect(_args(root))
                self.assertEqual(
                    {item["id"]: item for item in matching["checks"]}["restart.required"]["code"],
                    "matching",
                )
                _write(
                    hermes / "config.yaml",
                    "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                    "      chat_id: " + home_route + "\n    extra:\n"
                    "      welcomer_allowlist: " + first_id + "\n",
                )
                with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                    doctor, "_connector_report", return_value={"unsupported": True}
                ):
                    alias = doctor.collect(_args(root))
                self.assertEqual(
                    {item["id"]: item for item in alias["checks"]}["restart.required"]["code"],
                    "matching",
                )
                _write(
                    hermes / "config.yaml",
                    "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                    "      chat_id: " + home_route + "\n    extra:\n"
                    "      dm_allow_from: " + second_id + "\n",
                )
                with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                    doctor, "_connector_report", return_value={"unsupported": True}
                ):
                    replaced = doctor.collect(_args(root))
                self.assertEqual(
                    {item["id"]: item for item in replaced["checks"]}["restart.required"]["code"],
                    "restart_required",
                )
                observations.loaded_fingerprint = diag.config_fingerprint(
                    diag.nonsecret_config_fields(
                        senders=[],
                        allow_all=False,
                        welcomers=diag.resolve_welcomers({"dm_allow_from": [second_id]}),
                        account_id_hex=None,
                        socket_path=str(_args(root).socket),
                        home_route=home_route,
                        **_media_kwargs(_args(root).socket, fallback_home=home),
                    )
                )
                with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                    doctor, "_connector_report", return_value={"unsupported": True}
                ):
                    refreshed = doctor.collect(_args(root))
                self.assertEqual(
                    {item["id"]: item for item in refreshed["checks"]}["restart.required"]["code"],
                    "matching",
                )
            finally:
                plugin_server.stop()

    def test_dotenv_scalar_interpolation_and_quotes(self) -> None:
        environ = {"SYNTHETIC_TOKEN": "expanded-secret", "OTHER": "xy"}
        values, error, unsupported = diag.parse_dotenv_assignments(
            "MARMOT_AGENT_AUTH_TOKEN=${SYNTHETIC_TOKEN}\n"
            "MARMOT_HOME_CHANNEL=$OTHER\n"
            "MARMOT_AGENT_SOCKET='${SYNTHETIC_TOKEN}'\n"
            "MARMOT_ACCOUNT_ID_HEX=\"${OTHER}\"\n"
            "MARMOT_HOME=\\$OTHER\n"
            "MARMOT_INBOUND_MEDIA_DIR=${MISSING:-/fallback}\n",
            environ=environ,
        )
        self.assertIsNone(error)
        self.assertEqual(unsupported, frozenset())
        self.assertEqual(values["MARMOT_AGENT_AUTH_TOKEN"], "expanded-secret")
        self.assertEqual(values["MARMOT_HOME_CHANNEL"], "xy")
        self.assertEqual(values["MARMOT_AGENT_SOCKET"], "${SYNTHETIC_TOKEN}")
        self.assertEqual(values["MARMOT_ACCOUNT_ID_HEX"], "xy")
        self.assertEqual(values["MARMOT_HOME"], "$OTHER")
        self.assertEqual(values["MARMOT_INBOUND_MEDIA_DIR"], "/fallback")
        empty, empty_error, empty_unsupported = diag.parse_dotenv_assignments(
            "MARMOT_AGENT_AUTH_TOKEN=\nMARMOT_AGENT_SOCKET=\"\"\n",
            environ={"MARMOT_AGENT_AUTH_TOKEN": "stale"},
        )
        self.assertEqual(empty_unsupported, frozenset())
        self.assertIsNone(empty_error)
        self.assertEqual(empty["MARMOT_AGENT_AUTH_TOKEN"], "")
        self.assertEqual(empty["MARMOT_AGENT_SOCKET"], "")
        projected = diag.project_effective_env(
            empty, environ={"MARMOT_AGENT_AUTH_TOKEN": "stale", "MARMOT_AGENT_SOCKET": "/stale.sock"}
        )
        self.assertEqual(projected["MARMOT_AGENT_AUTH_TOKEN"], "")
        self.assertEqual(projected["MARMOT_AGENT_SOCKET"], "")

    def test_collect_empty_dotenv_clears_inherited_and_uses_yaml(self) -> None:
        yaml_home = "aa" * 16
        yaml_account = "11" * 32
        stale_home = "bb" * 16
        stale_account = "22" * 32
        with _short_tempdir("ee-") as raw:
            root = Path(raw)
            args = _args(root)
            home = _private_dir(Path(args.home))
            hermes = _private_dir(Path(args.hermes_home))
            _private_dir(Path(args.plugin_dir))
            yaml_socket = root / "y.sock"
            stale_socket = root / "s.sock"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + yaml_home + "\n    extra:\n"
                "      socket_path: " + str(yaml_socket) + "\n"
                "      account_id_hex: " + yaml_account + "\n"
                "      auth_token: yaml-inline-token\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_AGENT_SOCKET=\n"
                "MARMOT_ACCOUNT_ID_HEX=\n"
                "MARMOT_HOME_CHANNEL=\n"
                "MARMOT_AGENT_AUTH_TOKEN=\n",
            )
            connector = _ConnectorFixture(yaml_socket, expected_token="yaml-inline-token")
            connector.start()
            try:
                env = {
                    "MARMOT_AGENT_SOCKET": str(stale_socket),
                    "MARMOT_ACCOUNT_ID_HEX": stale_account,
                    "MARMOT_HOME_CHANNEL": stale_home,
                    "MARMOT_AGENT_AUTH_TOKEN": "stale-inherited-token",
                }
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    report = doctor.collect(args)
                self.assertTrue(connector.requests)
                self.assertEqual(connector.requests[0].get("auth_token"), "yaml-inline-token")
                self.assertEqual(connector.requests[0].get("account_id_hex"), yaml_account)
                self.assertEqual(connector.requests[0].get("home_group_id_hex"), yaml_home)
                by_id = {item["id"]: item for item in report["checks"]}
                self.assertNotEqual(by_id["account.selection"]["code"], "unauthorized")
                encoded = json.dumps(report) + diag.render_human(report)
                self.assertNotIn("yaml-inline-token", encoded)
                self.assertNotIn("stale-inherited-token", encoded)
                self.assertNotIn(str(yaml_socket), encoded)
                self.assertNotIn(yaml_account, encoded)
            finally:
                connector.stop()

    def test_collect_dotenv_interpolation_matches_host_expansion(self) -> None:
        yaml_home = "aa" * 16
        expanded_home = "cc" * 16
        expanded_account = "33" * 32
        with _short_tempdir("ei-") as raw:
            root = Path(raw)
            args = _args(root)
            _private_dir(Path(args.home))
            hermes = _private_dir(Path(args.hermes_home))
            _private_dir(Path(args.plugin_dir))
            yaml_socket = root / "y.sock"
            expanded_socket = root / "e.sock"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + yaml_home + "\n    extra:\n"
                "      socket_path: " + str(yaml_socket) + "\n"
                "      auth_token: yaml-inline-token\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_AGENT_SOCKET=${SYNTHETIC_SOCKET}\n"
                "MARMOT_ACCOUNT_ID_HEX=${SYNTHETIC_ACCOUNT}\n"
                "MARMOT_HOME_CHANNEL=${SYNTHETIC_HOME}\n"
                "MARMOT_AGENT_AUTH_TOKEN=${SYNTHETIC_TOKEN}\n",
            )
            connector = _ConnectorFixture(expanded_socket, expected_token="expanded-secret")
            connector.start()
            try:
                env = {
                    "SYNTHETIC_SOCKET": str(expanded_socket),
                    "SYNTHETIC_ACCOUNT": expanded_account,
                    "SYNTHETIC_HOME": expanded_home,
                    "SYNTHETIC_TOKEN": "expanded-secret",
                    "MARMOT_AGENT_SOCKET": "",
                    "MARMOT_ACCOUNT_ID_HEX": "",
                    "MARMOT_HOME_CHANNEL": "",
                    "MARMOT_AGENT_AUTH_TOKEN": "stale-inherited-token",
                }
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    for key in (
                        "MARMOT_AGENT_SOCKET",
                        "MARMOT_ACCOUNT_ID_HEX",
                        "MARMOT_HOME_CHANNEL",
                    ):
                        os.environ.pop(key, None)
                    report = doctor.collect(args)
                self.assertTrue(connector.requests)
                self.assertEqual(connector.requests[0].get("auth_token"), "expanded-secret")
                self.assertEqual(connector.requests[0].get("account_id_hex"), expanded_account)
                self.assertEqual(connector.requests[0].get("home_group_id_hex"), expanded_home)
                by_id = {item["id"]: item for item in report["checks"]}
                self.assertNotEqual(by_id["account.selection"]["code"], "unauthorized")
                encoded = json.dumps(report) + diag.render_human(report)
                self.assertNotIn("expanded-secret", encoded)
                self.assertNotIn("${SYNTHETIC_TOKEN}", encoded)
                self.assertNotIn("yaml-inline-token", encoded)
                self.assertNotIn(str(expanded_socket), encoded)
                self.assertNotIn(expanded_account, encoded)
            finally:
                connector.stop()

    def test_collect_inspects_configured_media_dirs_not_defaults(self) -> None:
        with _short_tempdir("md-") as raw:
            root = Path(raw)
            args = _args(root)
            home = _private_dir(Path(args.home))
            hermes = _private_dir(Path(args.hermes_home))
            _private_dir(Path(args.plugin_dir))
            default_in = _private_dir(home / "dev" / "inbound-media")
            default_out = _private_dir(home / "dev" / "outbound-media")
            configured_in = _unsafe_dir(root / "in-media")
            configured_out = _unsafe_dir(root / "out-media")
            missing = root / "lazy-media"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    extra:\n"
                "      inbound_media_dir: " + str(configured_in) + "\n"
                "      outbound_media_dir: " + str(configured_out) + "\n",
            )
            before = _tree_signature(root)
            with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                doctor, "_connector_report", return_value={"unsupported": True}
            ):
                report = doctor.collect(args)
            after = _tree_signature(root)
            self.assertEqual(before, after)
            by_id = {item["id"]: item for item in report["checks"]}
            self.assertEqual(by_id["files.inbound_dir"]["status"], "fatal")
            self.assertEqual(by_id["files.inbound_dir"]["code"], "unsafe_mode")
            self.assertEqual(by_id["files.outbound_dir"]["status"], "fatal")
            self.assertEqual(by_id["files.outbound_dir"]["code"], "unsafe_mode")
            self.assertEqual(diag.inspect_path(default_in, expect_dir=True)["status"], "healthy")
            self.assertEqual(diag.inspect_path(default_out, expect_dir=True)["status"], "healthy")
            extra = {"inbound_media_dir": str(configured_in), "outbound_media_dir": str(configured_out)}
            adapter_in = diag.resolve_inbound_media_dir(extra, args.socket, fallback_home=home)
            adapter_out = diag.resolve_outbound_media_dir(extra, args.socket, fallback_home=home)
            self.assertEqual(diag.inspect_path(adapter_in, expect_dir=True)["code"], "unsafe_mode")
            self.assertEqual(diag.inspect_path(adapter_out, expect_dir=True)["code"], "unsafe_mode")
            encoded = json.dumps(report) + diag.render_human(report)
            self.assertNotIn(str(configured_in), encoded)
            self.assertNotIn(str(configured_out), encoded)
            self.assertFalse(missing.exists())
            env = {
                "MARMOT_INBOUND_MEDIA_DIR": str(missing),
                "MARMOT_OUTBOUND_MEDIA_DIR": str(configured_out),
            }
            with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                diag, "bounded_run", return_value=None
            ), mock.patch.object(doctor, "_connector_report", return_value={"unsupported": True}):
                env_report = doctor.collect(args)
            env_ids = {item["id"]: item for item in env_report["checks"]}
            self.assertEqual(env_ids["files.inbound_dir"]["code"], "not_created")
            self.assertEqual(env_ids["files.inbound_dir"]["status"], "unknown")
            self.assertFalse(missing.exists())
            _write(
                hermes / ".env",
                "MARMOT_INBOUND_MEDIA_DIR=" + str(configured_in) + "\n"
                "MARMOT_OUTBOUND_MEDIA_DIR=" + str(configured_out) + "\n",
            )
            _write(hermes / "config.yaml", "platforms:\n  marmot:\n    extra: {}\n")
            with mock.patch.object(diag, "bounded_run", return_value=None), mock.patch.object(
                doctor, "_connector_report", return_value={"unsupported": True}
            ):
                dotenv_report = doctor.collect(args)
            dotenv_ids = {item["id"]: item for item in dotenv_report["checks"]}
            self.assertEqual(dotenv_ids["files.inbound_dir"]["code"], "unsafe_mode")
            self.assertEqual(dotenv_ids["files.outbound_dir"]["code"], "unsafe_mode")
            link = root / "link-media"
            link.symlink_to(configured_in)
            extra_link = {"inbound_media_dir": str(link)}
            link_checks = doctor._file_checks(
                extra_link, Path(args.socket), installer_home=home
            )
            link_ids = {item["id"]: item for item in link_checks}
            self.assertEqual(link_ids["files.inbound_dir"]["code"], "symlink")
            custom_socket = root / "custom" / "dev" / "wn-agent.sock"
            socket_home = custom_socket.parent.parent
            _private_dir(socket_home)
            socket_media = _unsafe_dir(socket_home / "dev" / "inbound-media")
            _unsafe_dir(socket_home / "dev" / "outbound-media")
            socket_checks = doctor._file_checks(
                {}, custom_socket, installer_home=home
            )
            socket_ids = {item["id"]: item for item in socket_checks}
            self.assertEqual(socket_ids["files.inbound_dir"]["code"], "unsafe_mode")
            self.assertEqual(diag.inspect_path(socket_media, expect_dir=True)["code"], "unsafe_mode")
            default_fields = diag.nonsecret_config_fields(
                senders=[],
                allow_all=False,
                welcomers=[],
                account_id_hex=None,
                socket_path=str(args.socket),
                home_route=None,
                **_media_kwargs(args.socket, fallback_home=home),
            )
            configured_fields = diag.nonsecret_config_fields(
                senders=[],
                allow_all=False,
                welcomers=[],
                account_id_hex=None,
                socket_path=str(args.socket),
                home_route=None,
                **_media_kwargs(args.socket, extra=extra, fallback_home=home),
            )
            self.assertNotEqual(
                diag.config_fingerprint(default_fields),
                diag.config_fingerprint(configured_fields),
            )

    def test_collect_unsupported_dotenv_does_not_send_stale_or_yaml_values(self) -> None:
        yaml_home = "aa" * 16
        yaml_account = "11" * 32
        stale_home = "bb" * 16
        stale_account = "22" * 32
        with _short_tempdir("eu-") as raw:
            root = Path(raw)
            args = _args(root)
            home = _private_dir(Path(args.home))
            hermes = _private_dir(Path(args.hermes_home))
            _private_dir(Path(args.plugin_dir))
            _private_dir(home / "dev" / "inbound-media")
            _private_dir(home / "dev" / "outbound-media")
            yaml_socket = root / "y.sock"
            _write(
                hermes / "config.yaml",
                "platforms:\n  marmot:\n    home_channel:\n      platform: marmot\n"
                "      chat_id: " + yaml_home + "\n    extra:\n"
                "      socket_path: " + str(yaml_socket) + "\n"
                "      account_id_hex: " + yaml_account + "\n"
                "      auth_token: yaml-inline-token\n",
            )
            _write(
                hermes / ".env",
                "MARMOT_AGENT_AUTH_TOKEN=${UNCLOSED\n"
                "MARMOT_INBOUND_MEDIA_DIR=${UNCLOSED\n",
            )
            connector = _ConnectorFixture(yaml_socket, expected_token="yaml-inline-token")
            connector.start()
            try:
                env = {
                    "MARMOT_AGENT_AUTH_TOKEN": "stale-inherited-token",
                    "MARMOT_ACCOUNT_ID_HEX": stale_account,
                    "MARMOT_HOME_CHANNEL": stale_home,
                }
                with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                    diag, "bounded_run", return_value=None
                ):
                    report = doctor.collect(args)
                self.assertEqual(connector.requests, [])
                by_id = {item["id"]: item for item in report["checks"]}
                self.assertEqual(by_id["account.selection"]["status"], "unknown")
                self.assertEqual(by_id["account.selection"]["code"], "unsupported")
                self.assertEqual(by_id["files.inbound_dir"]["status"], "unknown")
                self.assertEqual(by_id["files.inbound_dir"]["code"], "unsupported")
                self.assertEqual(by_id["files.outbound_dir"]["code"], "not_created")
                encoded = json.dumps(report) + diag.render_human(report)
                self.assertNotIn("stale-inherited-token", encoded)
                self.assertNotIn("yaml-inline-token", encoded)
                self.assertNotIn("${UNCLOSED", encoded)
                self.assertNotIn(str(yaml_socket), encoded)
                self.assertNotIn(stale_account, encoded)
                self.assertNotIn(yaml_account, encoded)
                values, error, unsupported = diag.parse_dotenv_assignments(
                    (hermes / ".env").read_text(encoding="utf-8"),
                    environ=env,
                )
                self.assertEqual(error, "unsupported")
                self.assertIn("MARMOT_AGENT_AUTH_TOKEN", unsupported)
                self.assertIn("MARMOT_INBOUND_MEDIA_DIR", unsupported)
                self.assertNotIn("MARMOT_AGENT_AUTH_TOKEN", values)
                projected = diag.project_effective_env(
                    values, environ=env, unsupported_keys=unsupported
                )
                self.assertNotIn("MARMOT_AGENT_AUTH_TOKEN", projected)
            finally:
                connector.stop()


class DiagnosticSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_socket_caps_and_refuses_foreign_paths(self) -> None:
        with _short_tempdir("ds-") as raw:
            root = Path(raw)
            hermes_home = root / "h"
            hermes_home.mkdir(mode=0o700)
            observations = diag.PluginObservations()
            observations.mark("awaiting_ack")
            server = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                observations,
            )
            self.assertTrue(await server.start())
            self.assertIsNotNone(server._server)
            self.addAsyncCleanup(server.stop)
            path = diag.diagnostics_socket_path(hermes_home)
            self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

            live = await diag.read_plugin_status(hermes_home)
            self.assertEqual(live["lifecycle"], "awaiting_ack")
            observations.mark("established")
            live = await diag.read_plugin_status(hermes_home)
            self.assertEqual(live["lifecycle"], "established")

            foreign = Path(raw) / "foreign.sock"
            foreign.symlink_to(path)
            with self.assertRaises(OSError):
                diag._bind_private_socket(foreign)

    async def test_status_socket_swallows_readline_value_error(self) -> None:
        with _short_tempdir("do-") as raw:
            hermes_home = Path(raw) / "h"
            hermes_home.mkdir(mode=0o700)
            server = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                diag.PluginObservations(),
            )
            self.assertTrue(await server.start())
            self.assertIsNotNone(server._server)
            self.addAsyncCleanup(server.stop)
            reader = mock.Mock()
            writer = mock.Mock()
            writer.drain = mock.AsyncMock()
            writer.wait_closed = mock.AsyncMock()
            reader.readline = mock.AsyncMock(side_effect=ValueError("oversize"))
            await server._handle(reader, writer)
            writer.close.assert_called()

    async def test_read_plugin_status_keeps_payload_if_close_fails(self) -> None:
        with _short_tempdir("cf-") as raw:
            hermes_home = Path(raw) / "h"
            sock = diag.diagnostics_socket_path(hermes_home)
            sock.parent.mkdir(parents=True, mode=0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(sock))
            self.addCleanup(listener.close)
            payload = {
                "schema_version": diag.SCHEMA_VERSION,
                "lifecycle": "established",
                "config_matches": True,
            }
            reader = mock.Mock()
            reader.readline = mock.AsyncMock(return_value=(json.dumps(payload) + "\n").encode("utf-8"))
            writer = mock.Mock()
            writer.drain = mock.AsyncMock()
            writer.wait_closed = mock.AsyncMock(side_effect=asyncio.TimeoutError())
            with mock.patch.object(asyncio, "open_unix_connection", mock.AsyncMock(return_value=(reader, writer))):
                live = await diag.read_plugin_status(hermes_home)
            self.assertEqual(live["lifecycle"], "established")
            self.assertTrue(live["config_matches"])
            writer.close.assert_called()

    async def test_status_socket_survives_permissive_umask(self) -> None:
        with _short_tempdir("dm-") as raw:
            previous = os.umask(0o022)
            try:
                hermes_home = Path(raw) / "h"
                hermes_home.mkdir(mode=0o700)
                os.chmod(hermes_home, 0o700)
                server = diag.DiagnosticSocketServer(
                    diag.diagnostics_socket_path(hermes_home),
                    diag.PluginObservations(),
                )
                self.assertTrue(await server.start())
                self.assertIsNotNone(server._server)
                self.addAsyncCleanup(server.stop)
                path = diag.diagnostics_socket_path(hermes_home)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            finally:
                os.umask(previous)

    async def test_start_returns_false_after_failed_bind_and_can_retry(self) -> None:
        with _short_tempdir("db-") as raw:
            hermes_home = Path(raw) / "h"
            hermes_home.mkdir(mode=0o700)
            first = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                diag.PluginObservations(),
            )
            self.assertTrue(await first.start())
            self.addAsyncCleanup(first.stop)
            second = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                diag.PluginObservations(),
            )
            self.assertFalse(await second.start())
            self.assertIsNone(second._server)
            await first.stop()
            self.assertTrue(await second.start())
            self.assertIsNotNone(second._server)
            self.addAsyncCleanup(second.stop)


class InstallerDoctorDispatchTests(unittest.TestCase):
    def test_json_requires_doctor(self) -> None:
        completed = subprocess.run(
            [str(INSTALLER), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--json requires --doctor", completed.stderr)

    def test_mutating_flags_rejected(self) -> None:
        completed = subprocess.run(
            [str(INSTALLER), "--doctor", "--yes"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("mutating", completed.stderr)

    def test_doctor_json_does_not_download_or_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="di-") as raw:
            root = Path(raw)
            home = root / "home"
            hermes = root / "hermes"
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text("#!/bin/sh\necho curl-was-invoked >&2\nexit 99\n", encoding="utf-8")
            os.chmod(curl, 0o755)
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            env["MARMOT_HOME"] = str(home)
            env["HERMES_HOME"] = str(hermes)
            env["MARMOT_INSTALL_PREFIX"] = str(root / "prefix")
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            before = _tree_signature(root)
            completed = subprocess.run(
                [str(INSTALLER), "--doctor", "--json", "--home", str(home), "--hermes-home", str(hermes)],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            after = _tree_signature(root)
            self.assertEqual(before, after)
            self.assertNotIn("curl-was-invoked", completed.stderr)
            self.assertNotIn("curl-was-invoked", completed.stdout)
            report = json.loads(completed.stdout)
            self.assertEqual(report["schema_version"], 1)
            self.assertIn(report["exit_code"], {0, 1, 2})
            encoded = completed.stdout + completed.stderr
            for canary in CANARIES:
                self.assertNotIn(canary, encoded)

    def test_installer_inline_token_beats_token_file(self) -> None:
        with _short_tempdir("ia-") as raw:
            root = Path(raw)
            home = root / "mh"
            hermes = root / "hh"
            home.mkdir(mode=0o700)
            hermes.mkdir(mode=0o700)
            (home / "dev").mkdir(mode=0o700)
            token_file = hermes / "tf"
            _write(token_file, "file-token-secret\n")
            sock = home / "dev" / "wn-agent.sock"
            connector = _ConnectorFixture(sock, expected_token="inline-token-secret")
            connector.start()
            try:
                env = os.environ.copy()
                env["PATH"] = env.get("PATH", "")
                env["MARMOT_HOME"] = str(home)
                env["HERMES_HOME"] = str(hermes)
                env["MARMOT_INSTALL_PREFIX"] = str(root / "prefix")
                env["MARMOT_AGENT_AUTH_TOKEN"] = "inline-token-secret"
                env["MARMOT_AGENT_AUTH_TOKEN_FILE"] = str(token_file)
                env["PYTHONDONTWRITEBYTECODE"] = "1"
                completed = subprocess.run(
                    [str(INSTALLER), "--doctor", "--json", "--home", str(home), "--hermes-home", str(hermes)],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )
                self.assertTrue(connector.requests)
                self.assertEqual(connector.requests[0].get("auth_token"), "inline-token-secret")
                report = json.loads(completed.stdout)
                self.assertNotEqual(report["checks"][0].get("code"), "unauthorized")
                encoded = completed.stdout + completed.stderr
                self.assertNotIn("inline-token-secret", encoded)
                self.assertNotIn("file-token-secret", encoded)
            finally:
                connector.stop()


def _tree_signature(root: Path) -> list[tuple[str, int, int]]:
    rows = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        rows.append((str(path.relative_to(root)), info.st_mode, info.st_size))
    return rows


class DoctorImportIsolationTests(unittest.TestCase):
    def test_doctor_does_not_import_adapter(self) -> None:
        self.assertNotIn("marmot.adapter", sys.modules)
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, %r); import marmot.doctor; "
                "raise SystemExit(int('marmot.adapter' in sys.modules or 'marmot.gateway' in sys.modules))"
                % str(HERMES_DIR),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
