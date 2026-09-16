#!/usr/bin/env python3
"""Privacy, fixture, and installer-dispatch tests for the Hermes Marmot doctor."""

from __future__ import annotations

import asyncio
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
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
        "home": str(root / "marmot-home"),
        "hermes_home": str(root / "hermes-home"),
        "plugin_dir": str(root / "plugin"),
        "socket": str(root / "marmot-home" / "dev" / "wn-agent.sock"),
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
        with tempfile.TemporaryDirectory(prefix="mdk-doctor-") as raw:
            root = Path(raw)
            home = root / "marmot-home"
            hermes = root / "hermes-home"
            plugin = root / "plugin"
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
        with tempfile.TemporaryDirectory(prefix="mdk-doctor-unsafe-") as raw:
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
        with tempfile.TemporaryDirectory(prefix="mdk-doctor-cfg-") as raw:
            root = Path(raw)
            home = root / "marmot-home"
            hermes = root / "hermes-home"
            plugin = root / "plugin"
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


class DiagnosticSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_socket_caps_and_refuses_foreign_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mdk-diag-sock-") as raw:
            root = Path(raw)
            hermes_home = root / "hermes"
            hermes_home.mkdir(mode=0o700)
            observations = diag.PluginObservations()
            observations.mark("awaiting_ack")
            server = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                observations,
            )
            await server.start()
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
        with tempfile.TemporaryDirectory(prefix="mdk-diag-oversize-") as raw:
            hermes_home = Path(raw) / "hermes"
            hermes_home.mkdir(mode=0o700)
            server = diag.DiagnosticSocketServer(
                diag.diagnostics_socket_path(hermes_home),
                diag.PluginObservations(),
            )
            await server.start()
            self.addAsyncCleanup(server.stop)
            reader = mock.Mock()
            writer = mock.Mock()
            writer.drain = mock.AsyncMock()
            writer.wait_closed = mock.AsyncMock()
            reader.readline = mock.AsyncMock(side_effect=ValueError("oversize"))
            await server._handle(reader, writer)
            writer.close.assert_called()

    async def test_status_socket_survives_permissive_umask(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mdk-diag-umask-") as raw:
            previous = os.umask(0o022)
            try:
                hermes_home = Path(raw) / "hermes"
                hermes_home.mkdir(mode=0o700)
                os.chmod(hermes_home, 0o700)
                server = diag.DiagnosticSocketServer(
                    diag.diagnostics_socket_path(hermes_home),
                    diag.PluginObservations(),
                )
                await server.start()
                self.addAsyncCleanup(server.stop)
                path = diag.diagnostics_socket_path(hermes_home)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            finally:
                os.umask(previous)


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
        with tempfile.TemporaryDirectory(prefix="mdk-doctor-install-") as raw:
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


def _tree_signature(root: Path) -> list[tuple[str, int, int]]:
    rows = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        rows.append((str(path.relative_to(root)), info.st_mode, info.st_size))
    return rows


class DoctorImportIsolationTests(unittest.TestCase):
    def test_doctor_does_not_import_adapter(self) -> None:
        self.assertNotIn("marmot.adapter", sys.modules)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
