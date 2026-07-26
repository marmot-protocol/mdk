import importlib.util
import os
import socket
import tempfile
import unittest
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


class PlatformRegistryHarness:
    """Minimal copy of Hermes' check, validate, then create registry flow."""

    def register_platform(self, **entry):
        self.entry = entry

    def create_adapter(self, config):
        if not self.entry["check_fn"]():
            return None
        validate = self.entry.get("validate_config")
        if validate is not None and not validate(config):
            return None
        return self.entry["adapter_factory"](config)


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
        saved_env = {key: os.environ.pop(key) for key in list(os.environ) if key.startswith("MARMOT_")}
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
                    platform_config = type(
                        "PlatformConfig",
                        (),
                        {"enabled": True, "extra": extra},
                    )()
                    registry = PlatformRegistryHarness()
                    adapter_module.register(registry)

                    adapter = registry.create_adapter(platform_config)

                    self.assertTrue(config["platforms"]["marmot"]["enabled"])
                    self.assertIsInstance(adapter, adapter_module.MarmotPlatformAdapter)
                    assert adapter is not None
                    self.assertEqual(adapter.socket_path, str(socket_path))
        finally:
            os.environ.update(saved_env)


if __name__ == "__main__":
    unittest.main()
