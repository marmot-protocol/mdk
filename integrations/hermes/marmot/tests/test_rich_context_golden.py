import json
import unittest
from pathlib import Path

from test_adapter import load_adapter_module


class RichContextGoldenTests(unittest.TestCase):
    def test_all_events_decode_and_deleted_targets_are_redacted(self):
        root = Path(__file__).resolve().parents[4]
        events = json.loads(
            (root / "fixtures" / "agent-control-v2-rich-context.json").read_text()
        )
        self.assertEqual(len(events), 8)
        adapter = load_adapter_module()
        decoded_inbound = [
            adapter._normalize_inbound_message_event(event)
            for event in events
            if event["type"] == "inbound_message"
        ]
        self.assertEqual(len(decoded_inbound), 4)
        self.assertTrue(all(event["message_id_hex"] for event in decoded_inbound))
        deleted = next(event for event in events if event["type"] == "message_deleted")
        self.assertEqual(deleted["target"]["availability"], "deleted")
        self.assertNotIn("text_excerpt", deleted["target"])
        self.assertNotIn("attachments", deleted["target"])


if __name__ == "__main__":
    unittest.main()
