import asyncio
import json
import os
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[4]
PROBE_DIR = Path(__file__).resolve().parent
if str(PROBE_DIR) not in sys.path:
    sys.path.insert(0, str(PROBE_DIR))

import progress_cleanup_probe as probe  # noqa: E402


class TestProgressCleanupProbeFailClosed(unittest.TestCase):
    def test_registered_hermes_home_requires_installed_plugin(self):
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}, clear=False):
                with self.assertRaisesRegex(AssertionError, "installed Marmot plugin"):
                    probe._registered_hermes_home()
            plugin = home / "plugins" / "marmot"
            plugin.mkdir(parents=True)
            (plugin / "adapter.py").write_text("# fixture\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"HERMES_HOME": str(home)}, clear=False):
                self.assertEqual(probe._registered_hermes_home(), home)

    def test_missing_delete_registry_entry_fails_without_private_fallback(self):
        fake_registry = types.SimpleNamespace(get_entry=lambda _name: None)
        fake_module = types.ModuleType("tools.registry")
        fake_module.registry = fake_registry
        with mock.patch.dict(sys.modules, {"tools": types.ModuleType("tools"), "tools.registry": fake_module}):
            with self.assertRaisesRegex(AssertionError, "was not registered"):
                probe._registered_delete_handler()
            probe._assert_missing_delete_registration_fails()

    def test_missing_platform_factory_fails_without_private_fallback(self):
        fake_registry = types.SimpleNamespace(create_adapter=lambda *_args, **_kwargs: None)
        fake_module = types.ModuleType("gateway.platform_registry")
        fake_module.platform_registry = fake_registry
        with mock.patch.dict(
            sys.modules,
            {
                "gateway": types.ModuleType("gateway"),
                "gateway.platform_registry": fake_module,
            },
        ):
            with self.assertRaisesRegex(AssertionError, "returned no adapter"):
                probe._create_registered_adapter(object())
            probe._assert_missing_factory_fails()

    def test_fresh_progress_state_fails_closed_when_attribute_missing(self):
        with self.assertRaisesRegex(AssertionError, "missing _tool_progress_events"):
            probe._assert_fresh_progress_state(object())
        with self.assertRaisesRegex(AssertionError, "reconstructed"):
            probe._assert_fresh_progress_state(types.SimpleNamespace(_tool_progress_events=None))
        with self.assertRaisesRegex(AssertionError, "reconstructed"):
            probe._assert_fresh_progress_state(
                types.SimpleNamespace(_tool_progress_events={"keep": {"synthetic"}})
            )
        probe._assert_fresh_progress_state(types.SimpleNamespace(_tool_progress_events={}))

    def test_home_env_restored_after_success_and_exception(self):
        original_home = os.environ.get("HOME")
        original_hermes = os.environ.get("HERMES_HOME")
        os.environ["HOME"] = "/tmp/progress-cleanup-home-original"
        os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-original"
        try:
            with probe._preserve_home_env():
                os.environ["HOME"] = "/tmp/progress-cleanup-home-mutated"
                os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-mutated"
            self.assertEqual(os.environ["HOME"], "/tmp/progress-cleanup-home-original")
            self.assertEqual(os.environ["HERMES_HOME"], "/tmp/progress-cleanup-hermes-original")
            with self.assertRaises(RuntimeError):
                with probe._preserve_home_env():
                    os.environ["HOME"] = "/tmp/progress-cleanup-home-failed"
                    os.environ["HERMES_HOME"] = "/tmp/progress-cleanup-hermes-failed"
                    raise RuntimeError("fixture failed")
            self.assertEqual(os.environ["HOME"], "/tmp/progress-cleanup-home-original")
            self.assertEqual(os.environ["HERMES_HOME"], "/tmp/progress-cleanup-hermes-original")
        finally:
            probe._restore_home_env(original_home, original_hermes)

    def test_scenario_control_socket_stays_under_unix_limit(self):
        path = probe._scenario_control_socket("accumulate")
        self.assertLess(len(os.fsencode(path)), probe.UNIX_SOCKET_PATH_LIMIT)
        self.assertTrue(path.name.endswith(".sock"))
        self.assertIn(str(os.getpid()), path.name)

    def test_wait_until_idle_fails_closed_on_timeout(self):
        server = probe.RecordingControlServer(Path("/tmp/progress-cleanup-unused.sock"))
        with self.assertRaisesRegex(AssertionError, "did not settle"):
            server.wait_until_idle(min_operations=1, quiet_s=0.01, timeout=0.05)
        server.operation_sends = 1
        server.wait_until_idle(min_operations=1, quiet_s=0.01, timeout=0.2)

    def test_control_server_closes_loop_when_bind_fails(self):
        server = probe.RecordingControlServer(Path("/tmp/progress-cleanup-bind-fail.sock"))
        loop = asyncio.new_event_loop()
        server._loop = loop

        async def boom():
            raise OSError("bind failed")

        server._bind = boom
        server._thread_main()
        self.assertTrue(loop.is_closed())
        self.assertIsInstance(server._error, OSError)
        self.assertTrue(server._ready.is_set())
        server.close_sync()
        self.assertTrue(loop.is_closed())

    def test_probe_final_ack_tracks_expected_answer_only(self):
        server = probe.RecordingControlServer(Path("/tmp/progress-cleanup-final.sock"))
        notice = server._response_for(
            {"id": "1", "type": "send_final", "text": "unrelated notice"},
            "send_final",
        )
        self.assertEqual(notice["type"], "final_sent")
        self.assertEqual(server.final_sends, 1)
        self.assertEqual(server.probe_final_acks, 0)
        wrapped = server._response_for(
            {"id": "2", "type": "send_final", "text": f"notice\n{probe.PROBE_FINAL_TEXT}\n"},
            "send_final",
        )
        self.assertEqual(wrapped["type"], "final_sent")
        self.assertEqual(server.final_sends, 2)
        self.assertEqual(server.probe_final_acks, 1)
        ack = server._response_for(
            {"id": "3", "type": "send_final", "text": probe.PROBE_FINAL_TEXT},
            "send_final",
        )
        self.assertEqual(ack["type"], "final_sent")
        self.assertEqual(server.final_sends, 3)
        self.assertEqual(server.probe_final_acks, 2)

    def test_acknowledges_probe_final_rejects_unrelated_text(self):
        self.assertFalse(probe._acknowledges_probe_final("unrelated notice"))
        self.assertFalse(probe._acknowledges_probe_final(""))
        self.assertTrue(probe._acknowledges_probe_final(f"  {probe.PROBE_FINAL_TEXT}  "))
        self.assertTrue(probe._acknowledges_probe_final(f"prefix\n{probe.PROBE_FINAL_TEXT}"))

    def test_retained_success_requires_probe_final_ack(self):
        result = {
            "resolved_cleanup": False,
            "operation_sends": 3,
            "logical_send_ids": ["marmot-tool-progress:1"],
            "durable_operation_ids": ["aa" * 32],
            "final_sends": 2,
            "probe_final_acks": 0,
            "delivery_boundary_observed": True,
            "scheduled_work_drained": True,
            "delete_attempts": [],
            "wire_deletes": 0,
            "delete_targets": [],
        }
        with self.assertRaisesRegex(AssertionError, "probe-final-ok"):
            probe._assert_retained_success(result, label="accumulate")
        result["probe_final_acks"] = 1
        probe._assert_retained_success(result, label="accumulate")

    def test_reconstructed_adapter_rejects_prior_durable_deletes(self):
        prior = ["cc" * 32]
        probe._assert_no_prior_durable_deletes(
            prior_durable_ids=prior,
            delete_attempts=[],
            delete_targets=[],
        )
        with self.assertRaisesRegex(AssertionError, "prior durable id"):
            probe._assert_no_prior_durable_deletes(
                prior_durable_ids=prior,
                delete_attempts=[prior[0]],
                delete_targets=[],
            )
        with self.assertRaisesRegex(AssertionError, "prior durable id"):
            probe._assert_no_prior_durable_deletes(
                prior_durable_ids=prior,
                delete_attempts=[],
                delete_targets=[prior[0]],
            )

    def test_control_server_answers_blocking_client_without_caller_loop(self):
        with tempfile.TemporaryDirectory() as raw:
            socket_path = Path(raw) / "control.sock"
            server = probe.RecordingControlServer(socket_path)
            server.start_sync()
            try:
                response = _blocking_control_request(
                    socket_path,
                    {
                        "marmot_agent_control": probe.PROTOCOL,
                        "id": "req-1",
                        "type": "send_agent_operation_event",
                        "name": "probe_alpha",
                        "preview": "alpha-preview",
                        "status": "started",
                    },
                )
                self.assertEqual(response["type"], "app_event_sent")
                self.assertEqual(server.operation_sends, 1)
                self.assertEqual(len(server.durable_operation_ids), 1)
            finally:
                server.close_sync()

    def test_blocking_client_from_running_loop_does_not_deadlock(self):
        async def scenario() -> dict[str, object]:
            with tempfile.TemporaryDirectory() as raw:
                socket_path = Path(raw) / "control.sock"
                server = probe.RecordingControlServer(socket_path)
                await server.start()
                try:
                    response = _blocking_control_request(
                        socket_path,
                        {
                            "marmot_agent_control": probe.PROTOCOL,
                            "id": "req-loop",
                            "type": "send_agent_operation_event",
                            "name": "probe_beta",
                            "preview": "beta-preview",
                            "status": "started",
                        },
                    )
                    server.wait_until_idle(min_operations=1, quiet_s=0.01, timeout=1.0)
                    return {
                        "type": response["type"],
                        "operation_sends": server.operation_sends,
                    }
                finally:
                    await server.close()

        observed = asyncio.run(scenario())
        self.assertEqual(observed["type"], "app_event_sent")
        self.assertEqual(observed["operation_sends"], 1)

    def test_apply_scenario_transport_overrides_loaded_extra(self):
        config = types.SimpleNamespace(enabled=False, extra={"socket_path": "/tmp/stale.sock"})
        with tempfile.TemporaryDirectory() as raw:
            socket_path = Path(raw) / "wn-agent.sock"
            agent_home = Path(raw) / "agent"
            applied = probe._apply_scenario_transport(
                config,
                socket_path=socket_path,
                agent_home=agent_home,
            )
        self.assertIs(applied, config)
        self.assertTrue(applied.enabled)
        self.assertEqual(applied.extra["socket_path"], str(socket_path))
        self.assertEqual(applied.extra["home"], str(agent_home))
        self.assertEqual(applied.extra["account_id_hex"], probe.ACCOUNT_ID_HEX)

    def test_bind_home_env_points_at_registered_home(self):
        original_home = os.environ.get("HOME")
        original_hermes = os.environ.get("HERMES_HOME")
        try:
            with tempfile.TemporaryDirectory() as raw:
                registered = Path(raw) / "registered"
                registered.mkdir()
                probe._bind_home_env(registered)
                self.assertEqual(os.environ["HERMES_HOME"], str(registered))
                self.assertEqual(os.environ["HOME"], str(registered.parent))
        finally:
            probe._restore_home_env(original_home, original_hermes)

    def test_seed_preserves_existing_plugin_entries(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        spec_name = "hermes_marmot_configure_gateway"
        if spec_name in sys.modules:
            helper = sys.modules[spec_name]
        else:
            helper = probe._load_helper()
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            home.mkdir(parents=True, exist_ok=True)
            (home / "config.yaml").write_text(
                "\n".join(
                    [
                        "plugins:",
                        "  entries:",
                        "    marmot:",
                        "      enabled: true",
                        "      settings:",
                        "        keep: retained",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            probe._write_seed_with_global_cleanup(home, helper)
            config = helper.load_config(home / "config.yaml")
            self.assertTrue(config["plugins"]["entries"]["marmot"]["enabled"])
            self.assertEqual(config["plugins"]["entries"]["marmot"]["settings"]["keep"], "retained")
            self.assertIs(config["display"]["cleanup_progress"], True)
            self.assertIs(config["display"]["platforms"]["marmot"]["cleanup_progress"], False)


def _blocking_control_request(socket_path: Path, payload: dict) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        sock.connect(os.fspath(socket_path))
        sock.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    finally:
        sock.close()
    if not raw:
        raise AssertionError("blocking control client received no response")
    return json.loads(raw.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
