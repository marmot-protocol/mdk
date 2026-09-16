#!/usr/bin/env python3
"""Privacy, fixture, and installer-dispatch tests for the Hermes Marmot doctor."""

from __future__ import annotations

import asyncio
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
        extra = {"group": None, "home_channel": None}
        self.assertIsNone(doctor._configured_home_route(extra, None))


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
