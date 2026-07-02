import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChannelMessageActionContext } from "openclaw/plugin-sdk/channel-contract";

import {
  createMarmotChannelPlugin,
  createMarmotDeleteActionAdapter,
  resolveMarmotChannelAccount,
  type MarmotMessageDeleteClient,
} from "../src/channel.js";
import {
  markMarmotInboundReady,
  markMarmotInboundReceived,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const HEX32 = (b: string) => b.repeat(32);

/** Read the `ok` flag from a `jsonResult`-shaped tool result's details payload. */
function resultOk(result: { details: unknown }): boolean {
  return (result.details as { ok?: boolean }).ok === true;
}

/** Read the `error` string from a `jsonResult`-shaped tool result's details payload. */
function resultError(result: { details: unknown }): string | undefined {
  return (result.details as { error?: string }).error;
}

function deleteCtx(params: Record<string, unknown>): ChannelMessageActionContext {
  return {
    channel: "marmot",
    action: "delete",
    cfg: {},
    params,
  } as unknown as ChannelMessageActionContext;
}

type Cfg = Parameters<typeof resolveMarmotChannelAccount>[0];

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
});

describe("resolveMarmotChannelAccount", () => {
  it("uses the root slice in single-account mode", () => {
    const cfg = { channels: { marmot: { socketPath: "/root.sock" } } } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/root.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/root.sock");
  });

  it("resolves accounts.default (and named accounts) in multi-account mode", () => {
    const cfg = {
      channels: {
        marmot: {
          accounts: {
            default: { socketPath: "/d.sock" },
            alice: { socketPath: "/a.sock" },
          },
        },
      },
    } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/d.sock");
    expect(resolveMarmotChannelAccount(cfg, "alice").socketPath).toBe("/a.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/d.sock");
  });

  it("throws for an unknown account id in multi-account mode", () => {
    const cfg = {
      channels: { marmot: { accounts: { default: { socketPath: "/d.sock" } } } },
    } as unknown as Cfg;
    expect(() => resolveMarmotChannelAccount(cfg, "bob")).toThrow(/unknown Marmot account/);
  });

  it("reports the active inbound subscription through channel status", async () => {
    const cfg = { channels: { marmot: { profileNameOnboarding: false } } } as unknown as Cfg;
    const plugin = createMarmotChannelPlugin();
    const status = plugin.status;
    if (!status?.buildAccountSnapshot || !status.buildChannelSummary) {
      throw new Error("Marmot plugin should expose channel status hooks");
    }
    const account = resolveMarmotChannelAccount(cfg, "default");
    const probe = { ok: true, accounts: 1, localSigningAccounts: 1 };

    markMarmotInboundReady("default");
    markMarmotInboundReceived("default");

    const snapshot = await status.buildAccountSnapshot({
      account,
      cfg,
      runtime: undefined,
      probe,
      audit: undefined,
    });
    expect(snapshot).toMatchObject({
      accountId: "default",
      running: true,
      connected: true,
      enabled: true,
      configured: true,
      mode: "block",
      dmPolicy: "allowlist",
      probe,
    });
    expect(snapshot.lastInboundAt).toEqual(expect.any(Number));

    const summary = await status.buildChannelSummary({
      account,
      cfg,
      defaultAccountId: "default",
      snapshot,
    });
    expect(summary).toMatchObject({
      configured: true,
      running: true,
      connected: true,
      mode: "block",
      probe,
    });
  });
});

describe("createMarmotDeleteActionAdapter", () => {
  it("declares the delete action through describeMessageTool", () => {
    const adapter = createMarmotDeleteActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: { deleteMessage: async () => undefined },
        marmotAccountIdHex: HEX32("aa"),
      }),
    });
    expect(adapter.describeMessageTool({ cfg: {} } as never)).toEqual({ actions: ["delete"] });
  });

  it("deletes via the send-time cache on a cache hit", async () => {
    const deleteByMessageId = vi.fn(async () => true);
    const resolveTarget = vi.fn(async () => ({
      client: { deleteMessage: vi.fn(async () => undefined) },
      marmotAccountIdHex: HEX32("aa"),
    }));
    const adapter = createMarmotDeleteActionAdapter({ deleteByMessageId, resolveTarget });

    const result = await adapter.handleAction!(deleteCtx({ messageId: HEX32("99") }));

    // The cache-hit delete must carry the action's routing context so it resolves
    // the correct account/client in a multi-account deployment.
    expect(deleteByMessageId).toHaveBeenCalledWith(HEX32("99"), {
      cfg: {},
      accountId: undefined,
    });
    expect(resolveTarget).not.toHaveBeenCalled();
    expect(resultOk(result)).toBe(true);
  });

  it("falls back to the explicit `to` group on a cache miss", async () => {
    const calls: { account: string; group: string; id: string }[] = [];
    const client: MarmotMessageDeleteClient = {
      deleteMessage: async (account, group, id) => {
        calls.push({ account, group, id });
        return undefined;
      },
    };
    const adapter = createMarmotDeleteActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({ client, marmotAccountIdHex: HEX32("aa") }),
    });

    const result = await adapter.handleAction!(
      deleteCtx({ messageId: HEX32("99"), to: HEX32("cc") }),
    );

    expect(calls).toEqual([
      { account: HEX32("aa"), group: HEX32("cc"), id: HEX32("99") },
    ]);
    expect(resultOk(result)).toBe(true);
  });

  it("returns an error when messageId is missing", async () => {
    const adapter = createMarmotDeleteActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: { deleteMessage: async () => undefined },
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(deleteCtx({}));
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/messageId required/);
  });

  it("errors on a cache miss with no `to` group to fall back to", async () => {
    const deleteMessage = vi.fn(async () => undefined);
    const adapter = createMarmotDeleteActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: { deleteMessage },
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(deleteCtx({ messageId: HEX32("99") }));
    expect(deleteMessage).not.toHaveBeenCalled();
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/could not resolve group/);
  });

  it("rejects an unsupported action", async () => {
    const adapter = createMarmotDeleteActionAdapter({
      deleteByMessageId: async () => true,
      resolveTarget: async () => ({
        client: { deleteMessage: async () => undefined },
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const ctx = { ...deleteCtx({ messageId: HEX32("99") }), action: "react" } as ChannelMessageActionContext;
    const result = await adapter.handleAction!(ctx);
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/unsupported action/);
  });
});
