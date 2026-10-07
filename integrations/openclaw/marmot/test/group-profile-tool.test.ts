import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentControlError } from "../src/client.js";

const mocks = vi.hoisted(() => ({
  update: vi.fn(),
  resolve: vi.fn(() => ({ marmotAccountIdHex: "11".repeat(32) })),
}));
vi.mock("../src/account.js", () => ({ resolveSingleAccount: vi.fn() }));
vi.mock("../src/channel.js", () => ({ resolveMarmotChannelAccount: mocks.resolve }));
vi.mock("../src/config.js", () => ({ clientForAccount: () => ({ groupProfileUpdate: mocks.update }) }));

import { createMarmotGroupProfileTool, registerMarmotGroupProfileTool } from "../src/group-profile-tool.js";

describe("marmot_group_profile", () => {
  beforeEach(() => vi.clearAllMocks());
  it("registers a model-callable tool", () => {
    const registerTool = vi.fn();
    registerMarmotGroupProfileTool({ config: {}, registerTool } as never);
    expect(registerTool.mock.calls[0]![1]).toEqual({ name: "marmot_group_profile" });
    expect(registerTool.mock.calls[0]![0]({ config: {} }).name).toBe("marmot_group_profile");
  });
  it("uses the current delivery account and preserves omitted/empty fields", async () => {
    mocks.update.mockResolvedValue({ type: "group_profile_updated", group_id_hex: "22".repeat(16), message_ids_hex: ["33".repeat(32)] });
    const tool = createMarmotGroupProfileTool({ config: {}, agentAccountId: "wrong", deliveryContext: { channel: "marmot", accountId: "current" } } as never, {});
    const result = await tool.execute("call", { group_id_hex: "22".repeat(16), description: "" });
    expect(mocks.resolve).toHaveBeenCalledWith({}, "current");
    expect(mocks.update).toHaveBeenCalledWith("11".repeat(32), "22".repeat(16), { description: "" });
    expect(result.details).toMatchObject({ ok: true });
  });
  it("rejects missing changes, wrong types and excessive UTF-8 bytes without connecting", async () => {
    const tool = createMarmotGroupProfileTool({ config: {} } as never, {});
    for (const patch of [{}, { name: "é".repeat(129) }, { description: "a".repeat(4097) }, { name: null }]) {
      expect((await tool.execute("call", { group_id_hex: "22".repeat(16), ...patch } as never)).details).toMatchObject({ ok: false });
    }
    expect(mocks.update).not.toHaveBeenCalled();
  });
  it("projects admin rejection without exposing server error prose", async () => {
    mocks.update.mockRejectedValue(new AgentControlError("private detail", { code: "not_group_admin" }));
    const result = await createMarmotGroupProfileTool({ config: {} } as never, {}).execute("call", { group_id_hex: "22".repeat(16), name: "New" });
    expect(result.details).toEqual({ ok: false, error: "not_group_admin", outcome: "rejected", retryable: false,
      control_retryable: false });
  });
  it("keeps post-commit control errors uncertain and preserves their retryability separately", async () => {
    const tool = createMarmotGroupProfileTool({ config: {} } as never, {});
    for (const [code, retryable] of [["app_error", false], ["app_error", true], ["not_group_admin", true]] as const) {
      mocks.update.mockRejectedValue(new AgentControlError("private detail", { code, retryable }));
      const result = await tool.execute("call", { group_id_hex: "22".repeat(16), name: "New" });
      expect(result.details).toMatchObject({ ok: false, outcome: "unknown", retryable: false,
        control_error: code, control_retryable: retryable });
      expect(JSON.stringify(result)).not.toContain("private detail");
    }
    expect(mocks.update).toHaveBeenCalledTimes(3);
  });
  it("never retries a timeout, EOF or malformed response", async () => {
    const tool = createMarmotGroupProfileTool({ config: {} } as never, {});
    for (const code of ["timeout", "socket_closed", "invalid_group_profile_response"]) {
      mocks.update.mockRejectedValue(new AgentControlError("private detail", { code, retryable: code !== "invalid_group_profile_response" }));
      expect((await tool.execute("call", { group_id_hex: "22".repeat(16), name: "New" })).details).toMatchObject({ ok: false, outcome: "unknown", retryable: false });
    }
    expect(mocks.update).toHaveBeenCalledTimes(3);
  });
});
