import json
import stat
import tempfile
import unittest
from pathlib import Path

import campaign


class CampaignTests(unittest.TestCase):
    def test_account_commands_can_bypass_not_yet_started_daemon(self) -> None:
        account = campaign.Account(
            campaign.Host("local"),
            "fips",
            "/data/fips",
            "/run/fips-lane.sock",
            "npub1test",
        )
        with_socket = account.wn_args("relays", "list")
        without_socket = account.wn_args("relays", "list", use_socket=False)
        self.assertIn("--socket", with_socket)
        self.assertNotIn("--socket", without_socket)

    def test_remote_docker_command_quotes_payload_as_one_ssh_argument(self) -> None:
        host = campaign.Host("remote", "root@example.test")
        command = host._docker_command("wn-client", ["wn", "messages", "send", "hello world"])
        self.assertEqual(command[-2], "root@example.test")
        self.assertEqual(command[-1], "docker exec wn-client wn messages send 'hello world'")

    def test_private_manifest_is_created_with_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            campaign.write_manifest(path, {"schema": campaign.SCHEMA})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_summary_parser_selects_summary_record(self) -> None:
        output = "\n".join(
            [
                json.dumps({"event": "run_start"}),
                json.dumps({"event": "summary", "failures": 0}),
            ]
        )
        self.assertEqual(campaign.parse_summary(output)["failures"], 0)

    def test_summary_validation_accepts_measured_failures(self) -> None:
        campaign.validate_benchmark_summary(
            {"samples_requested": 50, "samples_successful": 48, "failures": 2},
            50,
        )

    def test_summary_validation_rejects_unaccounted_samples(self) -> None:
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_benchmark_summary(
                {"samples_requested": 50, "samples_successful": 48, "failures": 1},
                50,
            )


if __name__ == "__main__":
    unittest.main()
