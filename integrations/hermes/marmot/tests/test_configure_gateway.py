import importlib.util
import os
import socket
import tempfile
import unittest
import unittest.mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT_PATH = REPO_ROOT / "scripts" / "hermes_marmot_configure_gateway.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "hermes_marmot_configure_gateway",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_adapter_module():
    helper_path = REPO_ROOT / "integrations" / "hermes" / "marmot" / "tests" / "test_adapter.py"
    spec = importlib.util.spec_from_file_location("hermes_marmot_test_adapter_helpers", helper_path)
    helper = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(helper)
    return helper.load_adapter_module()


class PlatformConfigHarness:
    def __init__(self, *, enabled=False, extra=None):
        self.enabled = enabled
        self.extra = extra or {}


class PlatformRegistryHarness:
    """Minimal copy of Hermes platform enablement and adapter creation."""

    def __init__(self):
        self.entry = {}

    def register_platform(self, **entry):
        self.entry = entry

    def apply_env_overrides(self, platform_config=None):
        """Mirror the relevant gateway.config._apply_env_overrides plugin gate."""
        existing = platform_config
        env_fn = self.entry.get("env_enablement_fn")
        seed = env_fn() if env_fn else None
        is_connected = self.entry.get("is_connected")
        if (existing is None or not existing.enabled) and is_connected is not None:
            probe_extra = dict(getattr(existing, "extra", {}) or {})
            if isinstance(seed, dict):
                for key, value in seed.items():
                    if key == "home_channel":
                        continue
                    probe_extra.setdefault(key, value)
            probe = PlatformConfigHarness(enabled=True, extra=probe_extra)
            if not is_connected(probe):
                return existing

        if not self.entry["check_fn"]():
            return existing
        if existing is None:
            existing = PlatformConfigHarness()
        existing.enabled = True
        if isinstance(seed, dict):
            existing.extra.update({key: value for key, value in seed.items() if key != "home_channel"})
        return existing

    def create_adapter(self, config):
        if not self.entry["check_fn"]():
            return None
        validate = self.entry.get("validate_config")
        if validate is not None and not validate(config):
            return None
        return self.entry["adapter_factory"](config)


def clear_marmot_env():
    saved = {key: os.environ.pop(key) for key in list(os.environ) if key.startswith("MARMOT_")}
    return saved


def restore_marmot_env(saved):
    for key in list(os.environ):
        if key.startswith("MARMOT_"):
            os.environ.pop(key)
    os.environ.update(saved)


class ConfigureGatewayTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_writes_marmot_platform_extra_and_final_only_defaults(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            config_path = self.module.configure_gateway_config(
                hermes_home=home,
                platform="marmot",
                streaming_enabled=False,
                streaming_transport="off",
                tool_progress="off",
                interim_assistant_messages=False,
                long_running_notifications=False,
                busy_ack_detail=False,
                agent_home=home / "marmot-agent",
                socket_path=home / "marmot-agent" / "dev" / "wn-agent.sock",
                account_id_hex="11" * 32,
                welcomer_allowlist=["22" * 32, "22" * 32],
            )

            config = self.module.load_config(config_path)

        self.assertNotIn("streaming", config)
        self.assertTrue(config["platforms"]["marmot"]["enabled"])
        extra = config["platforms"]["marmot"]["extra"]
        self.assertEqual(extra["home"], str(home / "marmot-agent"))
        self.assertEqual(
            extra["socket_path"],
            str(home / "marmot-agent" / "dev" / "wn-agent.sock"),
        )
        self.assertEqual(extra["account_id_hex"], "11" * 32)
        self.assertEqual(extra["welcomer_allowlist"], "22" * 32)
        marmot = config["display"]["platforms"]["marmot"]
        self.assertFalse(marmot["streaming"])
        self.assertEqual(marmot["tool_progress"], "off")
        self.assertFalse(marmot["interim_assistant_messages"])
        self.assertFalse(marmot["long_running_notifications"])
        self.assertFalse(marmot["busy_ack_detail"])

    def test_preserves_unrelated_config_and_platforms(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            config_path = home / "config.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "model: gpt-4o",
                        "agent:",
                        "  max_turns: 42",
                        "streaming:",
                        "  enabled: false",
                        "  edit_interval: 0.5",
                        "display:",
                        "  tool_progress: all",
                        "  platforms:",
                        "    telegram:",
                        "      tool_progress: verbose",
                        "platforms:",
                        "  telegram:",
                        "    extra:",
                        "      bot_token_file: /secret/token",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            self.module.configure_gateway_config(
                hermes_home=home,
                platform="marmot",
                streaming_enabled=False,
                streaming_transport="draft",
                tool_progress="new",
                interim_assistant_messages=True,
                long_running_notifications=True,
                busy_ack_detail=True,
                agent_home=home / "marmot-agent",
                socket_path=home / "marmot-agent" / "dev" / "wn-agent.sock",
                account_id_hex="11" * 32,
            )

            config = self.module.load_config(config_path)
            backups = sorted(home.glob("config.yaml.*.bak"))

        self.assertEqual(config["model"], "gpt-4o")
        self.assertEqual(config["agent"]["max_turns"], 42)
        self.assertFalse(config["streaming"]["enabled"])
        self.assertNotIn("transport", config["streaming"])
        self.assertEqual(config["streaming"]["edit_interval"], 0.5)
        self.assertEqual(config["display"]["tool_progress"], "all")
        self.assertEqual(
            config["display"]["platforms"]["telegram"]["tool_progress"],
            "verbose",
        )
        self.assertEqual(
            config["platforms"]["telegram"]["extra"]["bot_token_file"],
            "/secret/token",
        )
        self.assertEqual(
            config["platforms"]["marmot"]["extra"]["account_id_hex"],
            "11" * 32,
        )
        self.assertEqual(len(backups), 1)
        marmot = config["display"]["platforms"]["marmot"]
        self.assertFalse(marmot["streaming"])
        self.assertEqual(marmot["tool_progress"], "new")
        self.assertTrue(marmot["interim_assistant_messages"])
        self.assertTrue(marmot["long_running_notifications"])
        self.assertTrue(marmot["busy_ack_detail"])

    def test_rejects_invalid_bool(self):
        with self.assertRaises(ValueError):
            self.module.parse_bool("maybe", name="streaming")

    def test_can_update_global_streaming_when_explicit(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            config_path = self.module.configure_gateway_config(
                hermes_home=home,
                platform="marmot",
                streaming_enabled=True,
                streaming_transport="auto",
                tool_progress="off",
                interim_assistant_messages=False,
                long_running_notifications=False,
                busy_ack_detail=False,
                configure_global_streaming=True,
            )

            config = self.module.load_config(config_path)

        self.assertTrue(config["streaming"]["enabled"])
        self.assertEqual(config["streaming"]["transport"], "auto")
        self.assertTrue(config["display"]["platforms"]["marmot"]["streaming"])

    def test_persisted_config_creates_adapter_without_marmot_env(self):
        adapter_module = load_adapter_module()
        saved_env = clear_marmot_env()
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                home = Path(tempdir)
                agent_home = home / "marmot-agent"
                socket_dir = agent_home / "dev"
                socket_dir.mkdir(parents=True)
                socket_path = socket_dir / "wn-agent.sock"

                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.bind(str(socket_path))
                    server.listen(1)
                    self.assertTrue(socket_path.is_socket())

                    self.module.configure_gateway_config(
                        hermes_home=home,
                        platform="marmot",
                        streaming_enabled=False,
                        streaming_transport="off",
                        tool_progress="off",
                        interim_assistant_messages=False,
                        long_running_notifications=False,
                        busy_ack_detail=False,
                        agent_home=agent_home,
                        socket_path=socket_path,
                        account_id_hex="11" * 32,
                    )
                    config = self.module.load_config(home / "config.yaml")
                    extra = config["platforms"]["marmot"]["extra"]
                    platform_config = PlatformConfigHarness(enabled=True, extra=extra)
                    registry = PlatformRegistryHarness()
                    adapter_module.register(registry)

                    enabled_config = registry.apply_env_overrides(platform_config)
                    self.assertIs(enabled_config, platform_config)
                    adapter = registry.create_adapter(enabled_config)

                    self.assertTrue(config["platforms"]["marmot"]["enabled"])
                    self.assertIsInstance(adapter, adapter_module.MarmotPlatformAdapter)
                    assert adapter is not None
                    self.assertEqual(adapter.socket_path, str(socket_path))
        finally:
            restore_marmot_env(saved_env)


class MarmotPlatformEnablementTests(unittest.TestCase):
    def setUp(self):
        self.adapter_module = load_adapter_module()
        self.registry = PlatformRegistryHarness()
        self.adapter_module.register(self.registry)

    def test_register_wires_is_connected_for_env_override_gate(self):
        self.assertIs(self.registry.entry.get("is_connected"), self.adapter_module.validate_config)

    def test_unconfigured_platform_stays_disabled_without_marmot_env(self):
        saved_env = clear_marmot_env()
        try:
            with unittest.mock.patch.object(Path, "exists", return_value=False):
                self.assertIsNone(self.registry.apply_env_overrides())
        finally:
            restore_marmot_env(saved_env)

    def test_persisted_extra_wins_over_overlapping_env_seed_during_probe(self):
        saved_env = clear_marmot_env()
        probe_socket_paths: list[str] = []

        def capture_probe(config):
            probe_socket_paths.append(config.extra.get("socket_path", ""))
            return self.adapter_module.validate_config(config)

        original_is_connected = self.registry.entry["is_connected"]
        self.registry.entry["is_connected"] = capture_probe
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                persisted_socket = Path(tempdir) / "persisted.sock"
                conflicting_socket = Path(tempdir) / "conflicting.sock"
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.bind(str(persisted_socket))
                    server.listen(1)

                os.environ["MARMOT_AGENT_SOCKET"] = str(conflicting_socket)
                platform_config = PlatformConfigHarness(
                    enabled=False,
                    extra={"socket_path": str(persisted_socket)},
                )

                enabled_config = self.registry.apply_env_overrides(platform_config)

                self.assertEqual(probe_socket_paths, [str(persisted_socket)])
                self.assertIsNotNone(enabled_config)
                assert enabled_config is not None
                self.assertTrue(enabled_config.enabled)
        finally:
            self.registry.entry["is_connected"] = original_is_connected
            restore_marmot_env(saved_env)

    def test_environment_only_config_enables_and_creates_adapter(self):
        saved_env = clear_marmot_env()
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                socket_path = Path(tempdir) / "wn-agent.sock"
                os.environ["MARMOT_AGENT_SOCKET"] = str(socket_path)

                platform_config = self.registry.apply_env_overrides()
                self.assertIsNotNone(platform_config)
                assert platform_config is not None
                self.assertTrue(platform_config.enabled)
                self.assertEqual(platform_config.extra["socket_path"], str(socket_path))
                adapter = self.registry.create_adapter(platform_config)

                self.assertIsInstance(adapter, self.adapter_module.MarmotPlatformAdapter)
                assert adapter is not None
                self.assertEqual(adapter.socket_path, str(socket_path))
        finally:
            restore_marmot_env(saved_env)


if __name__ == "__main__":
    unittest.main()
