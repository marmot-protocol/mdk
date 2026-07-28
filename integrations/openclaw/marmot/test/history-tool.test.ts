import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  timelineMessageGet: vi.fn(),
  timelineList: vi.fn(),
  resolveMarmotChannelAccount: vi.fn(() => ({
    accountId: "named",
    marmotAccountIdHex: "11".repeat(32),
  })),
}));

vi.mock("../src/account.js", () => ({
  resolveSingleAccount: vi.fn(),
}));
vi.mock("../src/channel.js", () => ({
  resolveMarmotChannelAccount: mocks.resolveMarmotChannelAccount,
}));
vi.mock("../src/config.js", () => ({
  clientForAccount: () => ({
    timelineMessageGet: mocks.timelineMessageGet,
    timelineList: mocks.timelineList,
  }),
}));

import {
  createMarmotHistoryTool,
  registerMarmotHistoryTool,
} from "../src/history-tool.js";

describe("marmot_history tool registration", () => {
  it("registers one model-callable history tool during full plugin registration", () => {
    const registerTool = vi.fn();
    registerMarmotHistoryTool({
      config: {},
      registerTool,
    } as never);

    expect(registerTool).toHaveBeenCalledTimes(1);
    const [factory, options] = registerTool.mock.calls[0]!;
    expect(typeof factory).toBe("function");
    expect(options).toEqual({ name: "marmot_history" });
  });

  it("uses the active Marmot delivery account and fetches one exact message", async () => {
    mocks.timelineMessageGet.mockResolvedValueOnce({
      type: "timeline_message",
      message_id_hex: "22".repeat(32),
      message: null,
    });
    const tool = createMarmotHistoryTool(
      {
        config: {},
        agentAccountId: "wrong-agent-account",
        deliveryContext: { channel: "marmot", accountId: "named" },
      } as never,
      {},
    );
    const result = await tool.execute("call-1", {
      group_id_hex: "33".repeat(32),
      message_id_hex: "22".repeat(32),
    });

    expect(mocks.resolveMarmotChannelAccount).toHaveBeenCalledWith({}, "named");
    expect(mocks.timelineMessageGet).toHaveBeenCalledWith(
      "11".repeat(32),
      "33".repeat(32),
      "22".repeat(32),
    );
    expect(result.details).toEqual(
      expect.objectContaining({ ok: true, type: "timeline_message" }),
    );
  });

  it("pages older messages with a paired stable cursor", async () => {
    mocks.timelineList.mockResolvedValueOnce({
      type: "timeline_page",
      messages: [],
      has_more_before: false,
      has_more_after: false,
    });
    const tool = createMarmotHistoryTool({ config: {} } as never, {});
    await tool.execute("call-2", {
      group_id_hex: "33".repeat(32),
      before_recorded_at: 42,
      before_message_id_hex: "44".repeat(32),
      limit: 20,
    });

    expect(mocks.timelineList).toHaveBeenCalledWith(
      "11".repeat(32),
      "33".repeat(32),
      {
        before: {
          recorded_at: 42,
          message_id_hex: "44".repeat(32),
        },
        limit: 20,
      },
    );
  });
});
