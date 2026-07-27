import ast
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT_PATH = REPO_ROOT / "scripts" / "hermes_marmot_configure_gateway.py"
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install-hermes-marmot.sh"

NPUB_SAMPLE = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"
INVALID_NPUB = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
NPUB_HEX = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"
USER_A = "11" * 32
USER_B = "22" * 32
USER_C = "33" * 32


def load_module():
    scripts_dir = str(SCRIPT_PATH.parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(
        "hermes_marmot_configure_gateway",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
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


def scrub_marmot_env(env: dict[str, str] | None = None) -> dict[str, str]:
    base = dict(os.environ)
    for key in list(base):
        if key.startswith("MARMOT_"):
            base.pop(key, None)
    if env:
        base.update(env)
    return base


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
                with (
                    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as persisted_server,
                    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conflicting_server,
                ):
                    persisted_server.bind(str(persisted_socket))
                    persisted_server.listen(1)
                    conflicting_server.bind(str(conflicting_socket))
                    conflicting_server.listen(1)

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
                    self.assertEqual(enabled_config.extra["socket_path"], str(conflicting_socket))

                    adapter = self.registry.create_adapter(enabled_config)
                    self.assertIsInstance(adapter, self.adapter_module.MarmotPlatformAdapter)
                    assert adapter is not None
                    self.assertEqual(adapter.socket_path, str(conflicting_socket))
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


class ConfigureHermesEnvTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_fresh_env_writes_allowlist_and_disallow_all(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_A],
            )
            env_path = home / ".env"
            text = env_path.read_text(encoding="utf-8")
            state = self.module.read_hermes_env_auth(env_path)

            self.assertIn(f"MARMOT_ALLOWED_USERS={USER_A}", text)
            self.assertIn("MARMOT_ALLOW_ALL_USERS=false", text)
            self.assertEqual(state.allowed_users_hex, [USER_A])
            self.assertFalse(state.allow_all_users)
            self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)

    def test_normalizes_mixed_npub_and_hex_users(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[NPUB_SAMPLE, USER_B.upper(), f"0x{USER_C}"],
            )
            state = self.module.read_hermes_env_auth(home / ".env")

        self.assertEqual(
            state.allowed_users_hex,
            sorted([NPUB_HEX, USER_B, USER_C]),
        )

    def test_reinstall_unions_users_and_preserves_unrelated_env_lines(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "# gateway secrets",
                        "",
                        "OPENAI_API_KEY=secret",
                        f'MARMOT_ALLOWED_USERS = "{USER_A}"',
                        "MARMOT_ALLOW_ALL_USERS=false",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_B],
            )
            text = env_path.read_text(encoding="utf-8")
            state = self.module.read_hermes_env_auth(env_path)

        self.assertIn("OPENAI_API_KEY=secret", text)
        self.assertIn("# gateway secrets", text)
        self.assertEqual(state.allowed_users_hex, sorted([USER_A, USER_B]))
        self.assertFalse(state.allow_all_users)
        self.assertEqual(text.count("MARMOT_ALLOWED_USERS="), 1)
        self.assertEqual(text.count("MARMOT_ALLOW_ALL_USERS="), 1)

    def test_reinstall_without_new_users_preserves_existing_allowlist(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n",
                encoding="utf-8",
            )
            before = env_path.read_text(encoding="utf-8")
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[],
            )
            after = env_path.read_text(encoding="utf-8")

        self.assertEqual(before, after)

    def test_explicit_allow_all_opt_in(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_A],
                allow_all_opt_in=True,
            )
            state = self.module.read_hermes_env_auth(home / ".env")

        self.assertTrue(state.allow_all_users)

    def test_preserves_existing_allow_all_on_reinstall(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=true\n",
                encoding="utf-8",
            )
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_B],
            )
            state = self.module.read_hermes_env_auth(env_path)

        self.assertTrue(state.allow_all_users)
        self.assertEqual(state.allowed_users_hex, sorted([USER_A, USER_B]))

    def test_malformed_existing_env_fails_closed_without_modifying(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            original = "MARMOT_ALLOWED_USERS=not-a-valid-user\n"
            env_path.write_text(original, encoding="utf-8")
            with self.assertRaises(ValueError):
                self.module.configure_hermes_env(
                    hermes_home=home,
                    add_allowed_users=[USER_A],
                )
            self.assertEqual(env_path.read_text(encoding="utf-8"), original)

    def test_malformed_explicit_user_fails_closed(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with self.assertRaises(ValueError):
                self.module.configure_hermes_env(
                    hermes_home=home,
                    add_allowed_users=["npub1invalid"],
                )
            self.assertFalse((home / ".env").exists())

    def test_rejects_blank_explicit_user(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with self.assertRaises(ValueError):
                self.module.configure_hermes_env(
                    hermes_home=home,
                    add_allowed_users=["   "],
                )
            self.assertFalse((home / ".env").exists())

    def test_requires_explicit_auth_for_fresh_target(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with self.assertRaises(ValueError):
                self.module.configure_hermes_env(hermes_home=home)

    def test_existing_valid_auth_satisfies_requirement_without_new_users(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n",
                encoding="utf-8",
            )
            self.module.configure_hermes_env(hermes_home=home)
            state = self.module.read_hermes_env_auth(env_path)

        self.assertEqual(state.allowed_users_hex, [USER_A])

    def test_reads_exported_allowlist_and_allow_all(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        f"  export MARMOT_ALLOWED_USERS={USER_A}",
                        "export MARMOT_ALLOW_ALL_USERS=true",
                    ]
                ),
                encoding="utf-8",
            )
            state = self.module.read_hermes_env_auth(env_path)

        self.assertEqual(state.allowed_users_hex, [USER_A])
        self.assertTrue(state.allow_all_users)

    def test_preserves_export_prefix_when_rewriting_managed_env_lines(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        f"export MARMOT_ALLOWED_USERS={USER_A}",
                        "export MARMOT_ALLOW_ALL_USERS=false",
                    ]
                ),
                encoding="utf-8",
            )
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_B],
            )
            text = env_path.read_text(encoding="utf-8")

        self.assertIn(f"export MARMOT_ALLOWED_USERS={USER_A},{USER_B}", text)
        self.assertIn("export MARMOT_ALLOW_ALL_USERS=false", text)

    def test_reads_unquoted_inline_comments(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}  # phone user\n"
                "MARMOT_ALLOW_ALL_USERS=false  # keep restricted\n",
                encoding="utf-8",
            )
            state = self.module.read_hermes_env_auth(env_path)

        self.assertEqual(state.allowed_users_hex, [USER_A])
        self.assertFalse(state.allow_all_users)

    def test_reads_tab_before_inline_comments(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}\t# tabbed comment\n"
                "MARMOT_ALLOW_ALL_USERS=false\n",
                encoding="utf-8",
            )
            state = self.module.read_hermes_env_auth(env_path)

        self.assertEqual(state.allowed_users_hex, [USER_A])
        self.assertFalse(state.allow_all_users)

    def test_atomic_write_closes_fd_when_chmod_fails(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with mock.patch("os.chmod", side_effect=OSError("chmod failed")):
                with self.assertRaises(OSError):
                    self.module.configure_hermes_env(
                        hermes_home=home,
                        add_allowed_users=[USER_A],
                    )
            self.assertEqual(list(home.glob(".env.*")), [])
            self.assertFalse((home / ".env").exists())

    def test_last_assignment_wins_for_duplicate_managed_keys(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        f"MARMOT_ALLOWED_USERS={USER_A}",
                        "OPENAI_API_KEY=secret",
                        f"MARMOT_ALLOWED_USERS={USER_B}",
                        "MARMOT_ALLOW_ALL_USERS=false",
                    ]
                ),
                encoding="utf-8",
            )
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_C],
            )
            text = env_path.read_text(encoding="utf-8")
            state = self.module.read_hermes_env_auth(env_path)

        self.assertEqual(state.allowed_users_hex, sorted([USER_B, USER_C]))
        self.assertEqual(text.count("MARMOT_ALLOWED_USERS="), 1)
        self.assertIn("OPENAI_API_KEY=secret", text)

    def test_ambient_marmot_auth_env_does_not_broaden_target(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with mock.patch.dict(
                os.environ,
                {
                    "MARMOT_ALLOWED_USERS": USER_B,
                    "MARMOT_ALLOW_ALL_USERS": "true",
                },
                clear=False,
            ):
                with self.assertRaises(ValueError):
                    self.module.configure_hermes_env(hermes_home=home)

    def test_atomic_replace_uses_private_mode(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            self.module.configure_hermes_env(
                hermes_home=home,
                add_allowed_users=[USER_A],
            )
            env_path = home / ".env"
            mode = env_path.stat().st_mode
            self.assertEqual(mode & 0o777, 0o600)
            self.assertFalse(env_path.with_suffix(".env.bak").exists())

    def test_atomic_write_cleans_up_temp_file_on_failure(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            with mock.patch("os.replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    self.module.configure_hermes_env(
                        hermes_home=home,
                        add_allowed_users=[USER_A],
                    )
            leftovers = list(home.glob(".env.*"))
            self.assertEqual(leftovers, [])
            self.assertFalse((home / ".env").exists())


class ConfigureGatewayTransactionTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_env_dry_run_requires_configure_env_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes"
            env_path = hermes_home / ".env"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--env-dry-run",
                    "--allow-user",
                    USER_A,
                ],
                capture_output=True,
                text=True,
                env={**scrub_marmot_env(), "HERMES_HOME": str(hermes_home)},
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(
                "--env-dry-run requires --configure-env", completed.stderr
            )
            self.assertFalse(env_path.exists())

    def test_invalid_bool_leaves_env_and_config_byte_identical(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            config_path = home / "config.yaml"
            env_original = f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n"
            config_original = "model: gpt-4o\n"
            env_path.write_text(env_original, encoding="utf-8")
            config_path.write_text(config_original, encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--home",
                    str(home),
                    "--configure-env",
                    "--quiet",
                    "--allow-user",
                    USER_B,
                    "--agent-home",
                    str(home / "marmot-agent"),
                    "--streaming",
                    "maybe",
                ],
                capture_output=True,
                text=True,
                env=scrub_marmot_env(),
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(env_path.read_text(encoding="utf-8"), env_original)
            self.assertEqual(config_path.read_text(encoding="utf-8"), config_original)

    def test_config_write_failure_restores_env_byte_identical(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            config_path = home / "config.yaml"
            env_original = f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n"
            config_original = "model: gpt-4o\n"
            env_path.write_text(env_original, encoding="utf-8")
            config_path.write_text(config_original, encoding="utf-8")
            env_path.chmod(0o640)
            config_path.chmod(0o644)
            env_mode_original = env_path.stat().st_mode & 0o777
            config_mode_original = config_path.stat().st_mode & 0o777
            real_replace = os.replace
            replace_calls = {"count": 0}

            def replace_side_effect(src, dst, *args, **kwargs):
                replace_calls["count"] += 1
                if replace_calls["count"] == 2:
                    raise OSError("replace failed")
                return real_replace(src, dst, *args, **kwargs)

            with mock.patch("os.replace", side_effect=replace_side_effect):
                with self.assertRaises(OSError):
                    self.module.commit_env_and_config_transaction(
                        env_path=env_path,
                        env_lines=[
                            f"MARMOT_ALLOWED_USERS={USER_A},{USER_B}",
                            "MARMOT_ALLOW_ALL_USERS=false",
                        ],
                        config_path=config_path,
                        config_text="platforms: {}\n",
                        config_backup=False,
                    )
            self.assertEqual(replace_calls["count"], 3)
            self.assertEqual(env_path.read_text(encoding="utf-8"), env_original)
            self.assertEqual(config_path.read_text(encoding="utf-8"), config_original)
            self.assertEqual(env_path.stat().st_mode & 0o777, env_mode_original)
            self.assertEqual(config_path.stat().st_mode & 0o777, config_mode_original)
            self.assertFalse(
                config_path.with_suffix(config_path.suffix + ".tmp").exists()
            )

    def test_env_only_invalid_bool_leaves_env_byte_identical(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            env_original = f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n"
            env_path.write_text(env_original, encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--home",
                    str(home),
                    "--configure-env",
                    "--quiet",
                    "--allow-user",
                    USER_B,
                    "--streaming",
                    "maybe",
                ],
                capture_output=True,
                text=True,
                env=scrub_marmot_env(),
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(env_path.read_text(encoding="utf-8"), env_original)

    def test_malformed_existing_config_leaves_targets_byte_identical(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            env_path = home / ".env"
            config_path = home / "config.yaml"
            env_original = f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n"
            config_original = "model: gpt-4o\nplatforms: <<\n"
            env_path.write_text(env_original, encoding="utf-8")
            config_path.write_text(config_original, encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--home",
                    str(home),
                    "--configure-env",
                    "--quiet",
                    "--allow-user",
                    USER_B,
                    "--agent-home",
                    str(home / "marmot-agent"),
                    "--streaming",
                    "0",
                ],
                capture_output=True,
                text=True,
                env=scrub_marmot_env(),
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertEqual(env_path.read_text(encoding="utf-8"), env_original)
            self.assertEqual(config_path.read_text(encoding="utf-8"), config_original)


class ConfigureGatewayEnvDryRunTests(unittest.TestCase):
    def test_env_dry_run_with_ambient_marmot_home_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            ambient_home = home / "ambient-marmot"
            ambient_home.mkdir()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--home",
                    str(home / "hermes"),
                    "--configure-env",
                    "--env-dry-run",
                    "--quiet",
                    "--allow-user",
                    USER_A,
                ],
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "MARMOT_HOME": str(ambient_home),
                        "MARMOT_AGENT_SOCKET": str(ambient_home / "dev" / "wn-agent.sock"),
                        "MARMOT_ACCOUNT_ID_HEX": USER_B,
                    }
                ),
            )
            hermes_home = home / "hermes"
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((hermes_home / ".env").exists())
            self.assertFalse((hermes_home / "config.yaml").exists())


class ConfigureGatewayCliTests(unittest.TestCase):
    def test_streamed_auth_validator_matches_canonical_helper(self):
        canonical_source = SCRIPT_PATH.read_text(encoding="utf-8")
        installer_source = INSTALL_SCRIPT.read_text(encoding="utf-8")
        heredoc_start = installer_source.index(
            "        python3 - \"${args[@]+\"${args[@]}\"}\" <<'PY'\n"
        )
        embedded_start = installer_source.index("\n", heredoc_start) + 1
        embedded_end = installer_source.index("\nPY\n}", embedded_start)
        embedded_source = installer_source[embedded_start:embedded_end]

        canonical_tree = ast.parse(canonical_source)
        embedded_tree = ast.parse(embedded_source)

        def definitions(tree: ast.Module) -> dict[str, str]:
            return {
                node.name: ast.dump(node, include_attributes=False)
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }

        def assignments(tree: ast.Module) -> dict[str, str]:
            result: dict[str, str] = {}
            for node in tree.body:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    result[target.id] = ast.dump(node.value, include_attributes=False)
            return result

        canonical_definitions = definitions(canonical_tree)
        embedded_definitions = definitions(embedded_tree)
        for name in (
            "_bech32_polymod",
            "_convert_bits",
            "_npub_to_hex",
            "normalize_account_id",
            "_validate_account_id",
            "validate_sender_auth_entries",
            "_parse_dotenv_scalar",
            "_parse_allowed_users_value",
            "_managed_env_key",
        ):
            with self.subTest(definition=name):
                self.assertEqual(
                    embedded_definitions[name],
                    canonical_definitions[name],
                )

        canonical_assignments = assignments(canonical_tree)
        embedded_assignments = assignments(embedded_tree)
        for name in (
            "ACCOUNT_ID_HEX_RE",
            "_BECH32_CHARSET",
            "_BECH32_VALUES",
            "MANAGED_ENV_KEYS",
        ):
            with self.subTest(assignment=name):
                self.assertEqual(
                    embedded_assignments[name],
                    canonical_assignments[name],
                )

    def _write_mock_curl(self, tempdir: Path) -> tuple[Path, Path]:
        mock_bin = tempdir / "mock-bin"
        mock_bin.mkdir()
        curl_log = tempdir / "curl.log"
        curl_log.write_text("", encoding="utf-8")
        (mock_bin / "curl").write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    "set -euo pipefail",
                    'printf "%s\\n" "$2" >>"${CURL_LOG:?}"',
                    "exit 0",
                ]
            ),
            encoding="utf-8",
        )
        (mock_bin / "curl").chmod(0o755)
        return mock_bin, curl_log

    def _run_streamed_installer(
        self,
        tempdir: Path,
        extra_args: list[str],
        *,
        env_extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = scrub_marmot_env(
            {
                "WN_AGENT_SHA": "9.9.9",
                "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                **(env_extra or {}),
            }
        )
        return subprocess.run(
            ["bash", "-s", "--", *extra_args],
            input=INSTALL_SCRIPT.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_skip_auth_requirement_flag_removed(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--configure-env",
                "--skip-auth-requirement",
            ],
            capture_output=True,
            text=True,
            env=scrub_marmot_env(),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unrecognized arguments", completed.stderr)

    def test_installer_empty_allow_users_paths_run_under_nounset(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            cases = [
                ("allow-all", ["--allow-all-users"]),
                ("existing-auth", []),
            ]
            for name, extra_args in cases:
                with self.subTest(name=name):
                    home = root / name
                    home.mkdir()
                    if name == "existing-auth":
                        (home / ".env").write_text(
                            f"MARMOT_ALLOWED_USERS={USER_A}\n"
                            "MARMOT_ALLOW_ALL_USERS=false\n",
                            encoding="utf-8",
                        )
                    completed = subprocess.run(
                        [
                            "bash",
                            str(INSTALL_SCRIPT),
                            "--dry-run",
                            "--yes",
                            "--hermes-home",
                            str(home),
                            *extra_args,
                        ],
                        capture_output=True,
                        text=True,
                        env=scrub_marmot_env(),
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                    )
                    self.assertNotIn("unbound variable", completed.stderr)

    def test_installer_dry_run_accepts_allow_user(self):
        with tempfile.TemporaryDirectory() as tempdir:
            completed = subprocess.run(
                [
                    "bash",
                    str(INSTALL_SCRIPT),
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    tempdir,
                    "--allow-user",
                    USER_A,
                ],
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "WN_AGENT_SHA": "9.9.9",
                        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                    }
                ),
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout + completed.stderr
        self.assertIn("would configure Marmot message-sender authorization", output)
        self.assertNotIn(USER_A, output)

    def test_streamed_install_rejects_checksum_invalid_npub_before_download(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            mock_bin, curl_log = self._write_mock_curl(Path(tempdir))
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--no-service",
                    "--allow-user",
                    INVALID_NPUB,
                ],
                env_extra={
                    "PATH": f"{mock_bin}:/usr/bin:/bin",
                    "CURL_LOG": str(curl_log),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            combined = completed.stdout + completed.stderr
            self.assertNotIn("npub1qq", combined)
            self.assertEqual(curl_log.read_text(encoding="utf-8"), "")
            self.assertFalse((hermes_home / ".env").exists())
            self.assertFalse((hermes_home / "plugins" / "marmot").exists())

    def test_streamed_dry_run_accepts_valid_npub_without_helper(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--allow-user",
                    NPUB_SAMPLE,
                ],
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout + completed.stderr
        self.assertIn("would configure Marmot message-sender authorization", output)
        self.assertNotIn(NPUB_HEX, output)

    def test_streamed_dry_run_accepts_comma_separated_users_without_helper(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--allow-user",
                    f"{USER_A},{USER_B}",
                ],
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout + completed.stderr
        self.assertIn("would configure Marmot message-sender authorization", output)
        self.assertNotIn(USER_A, output)
        self.assertNotIn(USER_B, output)

    def test_streamed_non_dry_rejects_blank_allow_user_before_download(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            mock_bin, curl_log = self._write_mock_curl(Path(tempdir))
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--no-service",
                    "--allow-user",
                    "   ",
                ],
                env_extra={
                    "PATH": f"{mock_bin}:/usr/bin:/bin",
                    "CURL_LOG": str(curl_log),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(curl_log.read_text(encoding="utf-8"), "")
            self.assertFalse((hermes_home / ".env").exists())
            self.assertFalse((hermes_home / "plugins" / "marmot").exists())


    def test_guided_tty_read_failure_aborts_without_looping(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            completed = subprocess.run(
                [
                    "bash",
                    "-s",
                    "--",
                    "--hermes-home",
                    str(hermes_home),
                ],
                input=INSTALL_SCRIPT.read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "WN_AGENT_SHA": "9.9.9",
                        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                        "HERMES_INSTALLER_TEST_PROMPT_TTY": "/dev/null",
                    }
                ),
            )
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertIn("guided setup input is unavailable", combined)

    def test_installer_dry_run_rejects_bad_npub_without_helper(self):
        with tempfile.TemporaryDirectory() as tempdir:
            completed = subprocess.run(
                [
                    "bash",
                    "-s",
                    "--",
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    tempdir,
                    "--allow-user",
                    INVALID_NPUB,
                ],
                input=INSTALL_SCRIPT.read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "WN_AGENT_SHA": "9.9.9",
                        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                    }
                ),
            )
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertNotIn("npub1qq", combined)

    def test_installer_dry_run_rejects_missing_sender_without_helper(self):
        with tempfile.TemporaryDirectory() as tempdir:
            completed = subprocess.run(
                [
                    "bash",
                    "-s",
                    "--",
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    tempdir,
                ],
                input=INSTALL_SCRIPT.read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "WN_AGENT_SHA": "9.9.9",
                        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                    }
                ),
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_streamed_dry_run_accepts_valid_existing_env_without_helper(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            hermes_home.mkdir()
            (hermes_home / ".env").write_text(
                f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n",
                encoding="utf-8",
            )
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                ],
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout + completed.stderr
        self.assertIn("would preserve or update existing Marmot message-sender authorization", output)
        self.assertNotIn(USER_A, output)

    def test_streamed_non_dry_malformed_existing_env_fails_before_download(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            hermes_home.mkdir()
            env_original = "MARMOT_ALLOWED_USERS=not-a-valid-user\n"
            (hermes_home / ".env").write_text(env_original, encoding="utf-8")
            mock_bin, curl_log = self._write_mock_curl(Path(tempdir))
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--no-service",
                ],
                env_extra={
                    "PATH": f"{mock_bin}:/usr/bin:/bin",
                    "CURL_LOG": str(curl_log),
                },
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(curl_log.read_text(encoding="utf-8"), "")
            self.assertEqual((hermes_home / ".env").read_text(encoding="utf-8"), env_original)
            self.assertFalse((hermes_home / "plugins" / "marmot").exists())

    def test_streamed_dry_run_valid_existing_env_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            hermes_home.mkdir()
            env_original = f"MARMOT_ALLOWED_USERS={USER_A}\nMARMOT_ALLOW_ALL_USERS=false\n"
            (hermes_home / ".env").write_text(env_original, encoding="utf-8")
            completed = self._run_streamed_installer(
                Path(tempdir),
                [
                    "--dry-run",
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                ],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((hermes_home / ".env").read_text(encoding="utf-8"), env_original)

    def test_streamed_install_fails_before_download_without_sender_auth(self):
        with tempfile.TemporaryDirectory() as tempdir:
            hermes_home = Path(tempdir) / "hermes-home"
            completed = subprocess.run(
                [
                    "bash",
                    "-s",
                    "--",
                    "--yes",
                    "--hermes-home",
                    str(hermes_home),
                    "--no-service",
                ],
                input=INSTALL_SCRIPT.read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                env=scrub_marmot_env(
                    {
                        "WN_AGENT_SHA": "9.9.9",
                        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
                    }
                ),
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((hermes_home / ".env").exists())
        self.assertFalse((hermes_home / "plugins" / "marmot").exists())


if __name__ == "__main__":
    unittest.main()
