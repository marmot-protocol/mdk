import { describe, expect, it } from "vitest";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";

const HEX32 = (byte: string) => byte.repeat(32);

describe("pinned OpenClaw reply context", () => {
  it("keeps a self-authored quote body when the channel explicitly opts in", async () => {
    const context = await buildChannelInboundEventContext({
      channel: "marmot",
      accountId: "default",
      messageId: HEX32("dd"),
      timestamp: 1_721_000_000_000,
      from: HEX32("bb"),
      sender: { id: HEX32("bb"), name: "Alice" },
      conversation: { kind: "group", id: HEX32("cc") },
      route: {
        agentId: "agent",
        accountId: "default",
        routeSessionKey: "agent:marmot",
      },
      reply: { to: HEX32("cc"), replyToId: HEX32("11") },
      message: { rawBody: "new message", bodyForAgent: "new message" },
      supplemental: {
        quote: {
          id: HEX32("11"),
          body: "quoted body",
          sender: "Marmot Agent",
          isQuote: true,
          isSelf: true,
        },
      },
      resolveSupplementalMedia: true,
      suppressSelfQuoteBody: false,
    });

    expect(context.ReplyToId).toBe(HEX32("11"));
    expect(context.ReplyToBody).toBe("quoted body");
    expect(context.ReplyToSender).toBe("Marmot Agent");
  });
});
