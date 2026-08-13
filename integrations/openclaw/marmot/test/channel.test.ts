import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChannelMessageActionContext } from "openclaw/plugin-sdk/channel-contract";

import {
  createMarmotChannelPlugin,
  createMarmotMessageActionAdapter,
  resolveMarmotChannelAccount,
  type MarmotMessageActionClient,
} from "../src/channel.js";
import { AgentControlError } from "../src/client.js";
import {
  markMarmotInboundReady,
  markMarmotInboundReceived,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const HEX32 = (b: string) => b.repeat(32);

function messageActionClient(
  overrides: Partial<MarmotMessageActionClient> = {},
): MarmotMessageActionClient {
  return {
    deleteMessage: async () => undefined,
    sendReaction: async () => undefined,
    removeReaction: async () => undefined,
    ...overrides,
  };
}

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

function reactCtx(
  params: Record<string, unknown>,
  toolContext: { currentMessageId?: string; currentMessagingTarget?: string } = {},
): ChannelMessageActionContext {
  return {
    channel: "marmot",
    action: "react",
    cfg: {},
    params,
    toolContext,
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
      mode: "off",
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
      mode: "off",
      probe,
    });
  });
});

describe("createMarmotMessageActionAdapter", () => {
  it("owns delete and react so core durable sends can fall through", () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient(),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    expect(adapter.supportsAction?.({ action: "delete" })).toBe(true);
    expect(adapter.supportsAction?.({ action: "send" })).toBe(false);
    expect(adapter.supportsAction?.({ action: "react" })).toBe(true);
  });

  it("declares delete and react through describeMessageTool", () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient(),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });
    expect(adapter.describeMessageTool({ cfg: {} } as never)).toEqual({
      actions: ["delete", "react"],
    });
  });

  it("deletes via the send-time cache on a cache hit", async () => {
    const deleteByMessageId = vi.fn(async () => true);
    const resolveTarget = vi.fn(async () => ({
      client: messageActionClient({ deleteMessage: vi.fn(async () => undefined) }),
      marmotAccountIdHex: HEX32("aa"),
    }));
    const adapter = createMarmotMessageActionAdapter({ deleteByMessageId, resolveTarget });

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
    const client = messageActionClient({
      deleteMessage: async (account, group, id) => {
        calls.push({ account, group, id });
        return undefined;
      },
    });
    const adapter = createMarmotMessageActionAdapter({
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
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient(),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(deleteCtx({}));
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/messageId required/);
  });

  it("errors on a cache miss with no `to` group to fall back to", async () => {
    const deleteMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ deleteMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(deleteCtx({ messageId: HEX32("99") }));
    expect(deleteMessage).not.toHaveBeenCalled();
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/could not resolve group/);
  });

  it("adds a reaction to the current inbound message with a prefixed target", async () => {
    const sendReaction = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ sendReaction }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      reactCtx(
        { emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: `marmot:${HEX32("cc")}` },
      ),
    );

    expect(sendReaction).toHaveBeenCalledWith(
      HEX32("aa"),
      HEX32("cc"),
      HEX32("99"),
      "👀",
    );
    expect(resultOk(result)).toBe(true);
  });

  it("honors the message_id alias over the current inbound message", async () => {
    const sendReaction = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ sendReaction }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    await adapter.handleAction!(
      reactCtx(
        { message_id: HEX32("88"), emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: HEX32("cc") },
      ),
    );

    expect(sendReaction).toHaveBeenCalledWith(
      HEX32("aa"),
      HEX32("cc"),
      HEX32("88"),
      "👀",
    );
  });

  it("removes all reactions only when remove is explicit and emoji is empty", async () => {
    const removeReaction = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ removeReaction }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      reactCtx({
        messageId: HEX32("99"),
        to: `  MARMOT:0X${"C".repeat(64)}  `,
        remove: true,
        emoji: "",
      }),
    );

    expect(removeReaction).toHaveBeenCalledWith(HEX32("aa"), HEX32("cc"), HEX32("99"));
    expect(resultOk(result)).toBe(true);
  });

  it("rejects missing, empty, and non-string emoji without explicit removal", async () => {
    const resolveTarget = vi.fn(async () => ({
      client: messageActionClient(),
      marmotAccountIdHex: HEX32("aa"),
    }));
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget,
    });
    const toolContext = {
      currentMessageId: HEX32("99"),
      currentMessagingTarget: HEX32("cc"),
    };

    for (const params of [{}, { emoji: "" }, { emoji: 7 }]) {
      const result = await adapter.handleAction!(reactCtx(params, toolContext));
      expect(resultOk(result)).toBe(false);
      expect(resultError(result)).toMatch(/emoji/);
    }
    expect(resolveTarget).not.toHaveBeenCalled();
  });

  it("rejects an invalid explicit reaction target before resolving a client", async () => {
    const resolveTarget = vi.fn(async () => ({
      client: messageActionClient(),
      marmotAccountIdHex: HEX32("aa"),
    }));
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget,
    });

    const result = await adapter.handleAction!(
      reactCtx({ messageId: HEX32("99"), to: "marmot:not-hex", emoji: "👀" }),
    );

    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toBe("could not resolve group for this message id");
    expect(resolveTarget).not.toHaveBeenCalled();
  });

  it("treats an already-absent reaction as an idempotent removal", async () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({
          removeReaction: async () => {
            throw new AgentControlError("reaction was not active", {
              code: "reaction_not_found",
            });
          },
        }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      reactCtx(
        { remove: true, emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: HEX32("cc") },
      ),
    );

    expect(resultOk(result)).toBe(true);
    expect((result.details as { removed?: boolean }).removed).toBe(true);
  });

  it("removes the bot's reaction when remove is true even with an emoji", async () => {
    const removeReaction = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ removeReaction }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      reactCtx(
        { remove: true, emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: HEX32("cc") },
      ),
    );

    expect(removeReaction).toHaveBeenCalledWith(
      HEX32("aa"),
      HEX32("cc"),
      HEX32("99"),
      "👀",
    );
    expect(resultOk(result)).toBe(true);
  });

  it("returns a privacy-safe reaction failure", async () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({
          sendReaction: async () => { throw new Error("secret socket detail"); },
        }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      reactCtx(
        { emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: HEX32("cc") },
      ),
    );
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toBe("reaction operation failed");
    expect(resultError(result)).not.toContain("secret");
  });

  it("sanitizes failures while resolving a reaction target", async () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => {
        throw new Error("secret socket path");
      },
    });

    const result = await adapter.handleAction!(
      reactCtx(
        { emoji: "👀" },
        { currentMessageId: HEX32("99"), currentMessagingTarget: HEX32("cc") },
      ),
    );
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toBe("reaction operation failed");
    expect(resultError(result)).not.toContain("secret");
  });

  it("rejects an unsupported action", async () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => true,
      resolveTarget: async () => ({
        client: messageActionClient(),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const ctx = { ...deleteCtx({ messageId: HEX32("99") }), action: "edit" } as ChannelMessageActionContext;
    const result = await adapter.handleAction!(ctx);
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/unsupported action/);
  });
});
