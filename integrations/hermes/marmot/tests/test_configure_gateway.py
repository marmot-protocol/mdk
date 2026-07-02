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

    def test_writes_marmot_streaming_defaults(self):
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
            )

            config = self.module.load_config(config_path)

        self.assertTrue(config["streaming"]["enabled"])
        self.assertEqual(config["streaming"]["transport"], "auto")
        marmot = config["display"]["platforms"]["marmot"]
        self.assertTrue(marmot["streaming"])
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
            )

            config = self.module.load_config(config_path)

        self.assertEqual(config["model"], "gpt-4o")
        self.assertEqual(config["agent"]["max_turns"], 42)
        self.assertFalse(config["streaming"]["enabled"])
        self.assertEqual(config["streaming"]["transport"], "draft")
        self.assertEqual(config["streaming"]["edit_interval"], 0.5)
        self.assertEqual(config["display"]["tool_progress"], "all")
        self.assertEqual(
            config["display"]["platforms"]["telegram"]["tool_progress"],
            "verbose",
        )
        marmot = config["display"]["platforms"]["marmot"]
        self.assertFalse(marmot["streaming"])
        self.assertEqual(marmot["tool_progress"], "new")
        self.assertTrue(marmot["interim_assistant_messages"])
        self.assertTrue(marmot["long_running_notifications"])
        self.assertTrue(marmot["busy_ack_detail"])

    def test_rejects_invalid_bool(self):
        with self.assertRaises(ValueError):
            self.module.parse_bool("maybe", name="streaming")

    def test_transport_off_disables_platform_streaming(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            config_path = self.module.configure_gateway_config(
                hermes_home=home,
                platform="marmot",
                streaming_enabled=True,
                streaming_transport="off",
                tool_progress="off",
                interim_assistant_messages=False,
                long_running_notifications=False,
                busy_ack_detail=False,
            )

            config = self.module.load_config(config_path)

        self.assertTrue(config["streaming"]["enabled"])
        self.assertEqual(config["streaming"]["transport"], "off")
        self.assertFalse(config["display"]["platforms"]["marmot"]["streaming"])


if __name__ == "__main__":
    unittest.main()
