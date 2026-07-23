import importlib.util
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


if __name__ == "__main__":
    unittest.main()
