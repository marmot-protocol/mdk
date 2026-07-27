import { describe, expect, it } from "vitest";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";

import { createMarmotMessagingAdapter } from "../src/messaging.js";
import { createMarmotMessageAdapter } from "../src/outbound.js";
import type { MarmotAgentControlClient } from "../src/client.js";

const CHANNEL_ACCOUNT_ID = "default";
const GROUP_ID_HEX = "cc".repeat(32);
const MESSAGE_ID_HEX = "dd".repeat(32);
const SENDER_ACCOUNT_ID_HEX = "bb".repeat(32);

describe("buildChannelInboundEventContext (pinned SDK)", () => {
  it("binds the Marmot group as the current messaging target and preserves account id", async () => {
    const ctx = buildChannelInboundEventContext({
      channel: "marmot",
      accountId: CHANNEL_ACCOUNT_ID,
      messageId: MESSAGE_ID_HEX,
      from: SENDER_ACCOUNT_ID_HEX,
      sender: { id: SENDER_ACCOUNT_ID_HEX },
      conversation: { kind: "group", id: GROUP_ID_HEX },
      route: {
        agentId: "main",
        accountId: CHANNEL_ACCOUNT_ID,
        routeSessionKey: `agent:main:marmot:group:${GROUP_ID_HEX}`,
      },
      reply: { to: GROUP_ID_HEX },
      message: { rawBody: "hello", bodyForAgent: "hello" },
    });

    expect(ctx.AccountId).toBe(CHANNEL_ACCOUNT_ID);
    expect(ctx.To).toBe(GROUP_ID_HEX);
    expect(ctx.ChatType).toBe("group");
  });
});

describe("messaging adapter target normalization (adapter boundary)", () => {
  // The pinned OpenClaw SDK does not expose a stable public runner seam for
  // omitted-target message-tool sends. This test covers the Marmot messaging +
  // outbound adapters directly; turn-scoped delivery ownership is validated in
  // test/turn-coordination.test.ts.
  it("normalizes a bare group id through the messaging adapter for outbound send_final", async () => {
    const messaging = createMarmotMessagingAdapter();
    const resolved = await messaging.targetResolver!.resolveTarget!({
      cfg: {} as never,
      input: GROUP_ID_HEX,
      normalized: GROUP_ID_HEX,
    });
    expect(resolved).toEqual({ to: GROUP_ID_HEX, kind: "group", source: "normalized" });

    const sendCalls: { groupIdHex: string; text: string }[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, groupIdHex: string, text: string) {
        sendCalls.push({ groupIdHex, text });
        return { type: "final_sent", message_ids_hex: ["ee".repeat(32)] };
      },
    } as unknown as MarmotAgentControlClient;
    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({ client, marmotAccountIdHex: "aa".repeat(32) }),
    });
    await adapter.send!.text!({
      cfg: {},
      accountId: CHANNEL_ACCOUNT_ID,
      to: resolved!.to,
      text: "tool-send",
    } as never);

    expect(sendCalls).toEqual([{ groupIdHex: GROUP_ID_HEX, text: "tool-send" }]);
  });
});
