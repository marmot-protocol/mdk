import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { decodeAgentControlEvent } from "../src/client.js";

describe("agent-control rich-context golden fixtures", () => {
  it("decodes every event and keeps deleted target content redacted", () => {
    const path = new URL("../../../../fixtures/agent-control-v2-rich-context.json", import.meta.url);
    const events = (JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>[]).map(
      decodeAgentControlEvent,
    );
    expect(events).toHaveLength(8);
    const deleted = events.find((event) => event.type === "message_deleted");
    expect(deleted?.type).toBe("message_deleted");
    if (deleted?.type === "message_deleted") {
      expect(deleted.target.availability).toBe("deleted");
      expect(deleted.target.text_excerpt).toBeUndefined();
      expect(deleted.target.attachments).toBeUndefined();
    }
  });

  it("rejects the removed flat inbound wire shape", () => {
    expect(() =>
      decodeAgentControlEvent({
        type: "inbound_message",
        account_id_hex: "aa",
        group_id_hex: "bb",
        message_id_hex: "cc",
        sender_account_id_hex: "dd",
        text: "legacy",
      }),
    ).toThrow("inbound_message.message must be an object");
  });
});
