import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
PROBE_DIR = Path(__file__).resolve().parent
if str(PROBE_DIR) not in sys.path:
    sys.path.insert(0, str(PROBE_DIR))


class TestPinnedSourceCheckout(unittest.TestCase):
    def test_exports_plugin_tree_without_cloning_host_repo(self):
        import test_real_hermes_plugin as real

        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "mdk-source"
            plugin = source / "integrations" / "hermes" / "marmot"
            plugin.mkdir(parents=True)
            (plugin / "adapter.py").write_text("# pinned-plugin\n", encoding="utf-8")
            (plugin / "plugin.yaml").write_text("name: marmot\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(["git", "add", "integrations/hermes/marmot"], cwd=source, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=MDK compatibility test",
                    "-c",
                    "user.email=compatibility-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                cwd=source,
                check=True,
            )
            ref = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=source,
                text=True,
            ).strip()

            dest_root = Path(raw) / "temp-root"
            dest_root.mkdir()
            checkout = real._pinned_source_checkout(source, ref, dest_root)

            self.assertTrue((checkout / "integrations" / "hermes" / "marmot" / "adapter.py").is_file())
            self.assertEqual(
                (checkout / "integrations" / "hermes" / "marmot" / "adapter.py").read_text(
                    encoding="utf-8"
                ),
                "# pinned-plugin\n",
            )
            self.assertTrue((checkout / ".git").exists())
            log = subprocess.check_output(
                ["git", "log", "--oneline"],
                cwd=checkout,
                text=True,
            )
            self.assertIn("Pin Marmot plugin fixture", log)

    def test_real_checkout_from_this_repo_contains_adapter(self):
        import test_real_hermes_plugin as real

        ref = subprocess.check_output(
            ["git", "-c", "safe.directory=*", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as raw:
            checkout = real._pinned_source_checkout(REPO_ROOT, ref, Path(raw))
            adapter = checkout / "integrations" / "hermes" / "marmot" / "adapter.py"
            self.assertTrue(adapter.is_file())
            self.assertIn("class", adapter.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
