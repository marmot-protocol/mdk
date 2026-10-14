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
  beginMarmotAccountLifecycle,
  markMarmotAllowlistSyncResult,
  markMarmotInboundReady,
  markMarmotInboundReceived,
  markMarmotInboundStarting,
  markMarmotSenderPolicyResult,
  MARMOT_ALLOWLIST_SYNC_FAILED,
  MARMOT_SENDER_POLICY_INVALID,
  MARMOT_SENDER_POLICY_MISSING,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const HEX32 = (b: string) => b.repeat(32);

function messageActionClient(
  overrides: Partial<MarmotMessageActionClient> = {},
): MarmotMessageActionClient {
  return {
    deleteMessage: async () => undefined,
    editMessage: async () => undefined,
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

function editCtx(
  params: Record<string, unknown>,
  toolContext: { currentMessagingTarget?: string; currentChannelId?: string } = {},
): ChannelMessageActionContext {
  return {
    channel: "marmot",
    action: "edit",
    cfg: {},
    params,
    toolContext,
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

  it("does not merge a sibling account's senderPolicy", () => {
    const allowed = HEX32("bb");
    const cfg = {
      channels: {
        marmot: {
          senderPolicy: { allowAll: true },
          accounts: {
            default: { senderPolicy: { allowedUsers: [allowed] } },
            other: {},
          },
        },
      },
    } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").senderPolicy).toMatchObject({
      state: "allowlist",
      allowedUsers: [allowed],
    });
    expect(resolveMarmotChannelAccount(cfg, "other").senderPolicy.state).toBe("missing");
  });

  it("throws for an unknown account id in multi-account mode", () => {
    const cfg = {
      channels: { marmot: { accounts: { default: { socketPath: "/d.sock" } } } },
    } as unknown as Cfg;
    expect(() => resolveMarmotChannelAccount(cfg, "bob")).toThrow(/unknown Marmot account/);
  });

  it("reports the active inbound subscription through channel status", async () => {
    const cfg = {
      channels: {
        marmot: {
          profileNameOnboarding: false,
          senderPolicy: { allowedUsers: [HEX32("bb")] },
        },
      },
    } as unknown as Cfg;
    const plugin = createMarmotChannelPlugin();
    const status = plugin.status;
    if (!status?.buildAccountSnapshot || !status.buildChannelSummary) {
      throw new Error("Marmot plugin should expose channel status hooks");
    }
    const account = resolveMarmotChannelAccount(cfg, "default");
    const probe = { ok: true, accounts: 1, localSigningAccounts: 1 };

    markMarmotSenderPolicyResult("default", { state: "allowlist", allowedUserCount: 1 });
    markMarmotInboundStarting("default");
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
    expect(snapshot).not.toHaveProperty("allowFrom");

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

  it("prefers a supplied host runtime, including a deliberate null lastError", async () => {
    const cfg = {
      channels: {
        marmot: {
          dm: { allowFrom: [HEX32("11")] },
          profileNameOnboarding: false,
          senderPolicy: { allowedUsers: [HEX32("bb")] },
        },
      },
    } as unknown as Cfg;
    const plugin = createMarmotChannelPlugin();
    const status = plugin.status;
    if (!status?.buildAccountSnapshot || !status.collectStatusIssues) {
      throw new Error("Marmot plugin should expose channel status hooks");
    }
    const account = resolveMarmotChannelAccount(cfg, "default");
    beginMarmotAccountLifecycle("default");
    markMarmotAllowlistSyncResult("default", { state: "failed", reason: "unverified" });
    markMarmotInboundStarting("default");
    markMarmotInboundReady("default");

    const fallback = await status.buildAccountSnapshot({
      account,
      cfg,
      runtime: undefined,
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(fallback).toMatchObject({
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });
    expect(fallback).not.toHaveProperty("allowFrom");
    expect(JSON.stringify(fallback)).not.toContain(HEX32("11"));

    const host = await status.buildAccountSnapshot({
      account,
      cfg,
      runtime: {
        accountId: "default",
        running: true,
        connected: false,
        lastError: null,
      },
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(host).toMatchObject({
      connected: false,
      lastError: null,
    });
    expect(host).not.toHaveProperty("allowFrom");

    const issues = status.collectStatusIssues([fallback]);
    expect(JSON.stringify(issues)).toContain(MARMOT_ALLOWLIST_SYNC_FAILED);
    expect(JSON.stringify(issues)).not.toContain(HEX32("11"));
  });

  it("uses lifecycle-bound sender readiness for supplied host snapshots", async () => {
    const plugin = createMarmotChannelPlugin();
    const status = plugin.status;
    if (!status?.buildAccountSnapshot || !status.probeAccount) {
      throw new Error("Marmot plugin should expose channel status hooks");
    }
    const healthyRuntime = {
      accountId: "default",
      running: true,
      connected: true,
      lastError: null,
    };
    const allowed = HEX32("bb");
    const cases: Array<{
      label: string;
      cfg: Cfg;
      error: string;
    }> = [
      {
        label: "missing",
        cfg: { channels: { marmot: { profileNameOnboarding: false } } } as unknown as Cfg,
        error: MARMOT_SENDER_POLICY_MISSING,
      },
      {
        label: "empty",
        cfg: {
          channels: { marmot: { senderPolicy: { allowedUsers: [] }, profileNameOnboarding: false } },
        } as unknown as Cfg,
        error: MARMOT_SENDER_POLICY_MISSING,
      },
      {
        label: "malformed",
        cfg: {
          channels: {
            marmot: { senderPolicy: { allowedUsers: ["nope"] }, profileNameOnboarding: false },
          },
        } as unknown as Cfg,
        error: MARMOT_SENDER_POLICY_INVALID,
      },
    ];

    for (const testCase of cases) {
      const account = resolveMarmotChannelAccount(testCase.cfg, "default");
      beginMarmotAccountLifecycle("default");
      markMarmotSenderPolicyResult("default", {
        state: testCase.label === "malformed" ? "invalid" : "missing",
        allowedUserCount: 0,
      });
      markMarmotInboundReady("default");
      const snapshot = await status.buildAccountSnapshot({
        account,
        cfg: testCase.cfg,
        runtime: healthyRuntime,
        probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
        audit: undefined,
      });
      expect(snapshot, testCase.label).toMatchObject({
        connected: false,
        lastError: testCase.error,
      });
      expect(JSON.stringify(snapshot), testCase.label).not.toContain(allowed);
    }

    const missingAccount = resolveMarmotChannelAccount(cases[0]!.cfg, "default");
    const operationalError = await status.buildAccountSnapshot({
      account: missingAccount,
      cfg: cases[0]!.cfg,
      runtime: { ...healthyRuntime, lastError: MARMOT_ALLOWLIST_SYNC_FAILED },
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(operationalError).toMatchObject({
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });

    const validCfg = {
      channels: {
        marmot: {
          senderPolicy: { allowedUsers: [allowed] },
          profileNameOnboarding: false,
        },
      },
    } as unknown as Cfg;
    const validAccount = resolveMarmotChannelAccount(validCfg, "default");
    beginMarmotAccountLifecycle("default");
    markMarmotSenderPolicyResult("default", { state: "allowlist", allowedUserCount: 1 });
    markMarmotInboundReady("default");
    const valid = await status.buildAccountSnapshot({
      account: validAccount,
      cfg: validCfg,
      runtime: healthyRuntime,
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(valid).toMatchObject({ connected: true, lastError: null });

    const editedCfg = {
      channels: {
        marmot: {
          senderPolicy: { allowedUsers: ["nope"] },
          profileNameOnboarding: false,
        },
      },
    } as unknown as Cfg;
    const beforeRestart = await status.buildAccountSnapshot({
      account: resolveMarmotChannelAccount(editedCfg, "default"),
      cfg: editedCfg,
      runtime: healthyRuntime,
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(beforeRestart).toMatchObject({ connected: true, lastError: null });

    beginMarmotAccountLifecycle("default");
    markMarmotSenderPolicyResult("default", { state: "invalid", allowedUserCount: 0 });
    markMarmotInboundReady("default");
    const afterRestart = await status.buildAccountSnapshot({
      account: resolveMarmotChannelAccount(editedCfg, "default"),
      cfg: editedCfg,
      runtime: healthyRuntime,
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(afterRestart).toMatchObject({
      connected: false,
      lastError: MARMOT_SENDER_POLICY_INVALID,
    });

    const namedCfg = {
      channels: {
        marmot: {
          accounts: {
            default: { senderPolicy: { allowedUsers: [allowed] } },
            other: {},
          },
        },
      },
    } as unknown as Cfg;
    beginMarmotAccountLifecycle("default");
    markMarmotSenderPolicyResult("default", { state: "allowlist", allowedUserCount: 1 });
    markMarmotInboundReady("default");
    beginMarmotAccountLifecycle("other");
    markMarmotSenderPolicyResult("other", { state: "missing", allowedUserCount: 0 });
    markMarmotInboundReady("other");
    const namedValid = await status.buildAccountSnapshot({
      account: resolveMarmotChannelAccount(namedCfg, "default"),
      cfg: namedCfg,
      runtime: { ...healthyRuntime, accountId: "default" },
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    const namedMissing = await status.buildAccountSnapshot({
      account: resolveMarmotChannelAccount(namedCfg, "other"),
      cfg: namedCfg,
      runtime: { ...healthyRuntime, accountId: "other" },
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(namedValid).toMatchObject({ connected: true, lastError: null });
    expect(namedMissing).toMatchObject({
      connected: false,
      lastError: MARMOT_SENDER_POLICY_MISSING,
    });
    expect(JSON.stringify({ namedValid, namedMissing })).not.toContain(allowed);
  });

  it("keeps security.dm.resolveAllowFrom on the account config", async () => {
    const cfg = {
      channels: { marmot: { dm: { allowFrom: [HEX32("11")] }, profileNameOnboarding: false } },
    } as unknown as Cfg;
    const account = resolveMarmotChannelAccount(cfg, "default");
    const plugin = createMarmotChannelPlugin();
    const snapshot = await plugin.status?.buildAccountSnapshot?.({
      account,
      cfg,
      runtime: undefined,
      probe: { ok: true, accounts: 1, localSigningAccounts: 1 },
      audit: undefined,
    });
    expect(account.allowFrom).toEqual([HEX32("11")]);
    expect(snapshot).not.toHaveProperty("allowFrom");
    expect(JSON.stringify(snapshot)).not.toContain(HEX32("11"));
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

  it("declares delete, edit and react through describeMessageTool", () => {
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient(),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });
    expect(adapter.describeMessageTool({ cfg: {} } as never)).toEqual({
      actions: ["delete", "edit", "react"],
    });
  });

  it("edits a sent message routed through the send-time cache", async () => {
    const editMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      sentTargetFor: (id) =>
        id === HEX32("99") ? { marmotAccountIdHex: HEX32("ab"), groupIdHex: HEX32("cd") } : undefined,
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      editCtx({ messageId: HEX32("99"), message: "status: done" }),
    );

    expect(editMessage).toHaveBeenCalledWith(HEX32("ab"), HEX32("cd"), HEX32("99"), "status: done");
    expect(resultOk(result)).toBe(true);
  });

  it("refuses to edit a cached message from another conversation than the authorized target", async () => {
    const editMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      sentTargetFor: () => ({ marmotAccountIdHex: HEX32("ab"), groupIdHex: HEX32("bb") }),
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    // The host authorized group A (explicit `to`, or the current conversation);
    // the message was sent to group B. Nothing may be published to B.
    const explicit = await adapter.handleAction!(
      editCtx({ messageId: HEX32("99"), message: "x", to: HEX32("cc") }),
    );
    const current = await adapter.handleAction!(
      editCtx(
        { messageId: HEX32("99"), message: "x" },
        { currentMessagingTarget: `marmot:${HEX32("cc")}` },
      ),
    );

    for (const result of [explicit, current]) {
      expect(resultOk(result)).toBe(false);
      expect(resultError(result)).toMatch(/different conversation/);
    }
    expect(editMessage).not.toHaveBeenCalled();
  });

  it("treats the bound turn's currentChannelId as the authorized group", async () => {
    const editMessage = vi.fn(async () => undefined);
    const cache = new Map([[HEX32("99"), { marmotAccountIdHex: HEX32("ab"), groupIdHex: HEX32("bb") }]]);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      sentTargetFor: (id) => cache.get(id),
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });
    // Pinned OpenClaw binds a Marmot turn via currentChannelId only; the
    // documented call has no `to`, so the host's cross-context guard sees none.
    const bound = { currentChannelId: HEX32("cc") };

    const crossConversation = await adapter.handleAction!(
      editCtx({ messageId: HEX32("99"), message: "x" }, bound),
    );
    expect(resultError(crossConversation)).toMatch(/different conversation/);
    expect(editMessage).not.toHaveBeenCalled();

    const cacheMiss = await adapter.handleAction!(
      editCtx({ messageId: HEX32("98"), message: "status: done" }, bound),
    );
    expect(resultOk(cacheMiss)).toBe(true);
    expect(editMessage).toHaveBeenCalledWith(HEX32("aa"), HEX32("cc"), HEX32("98"), "status: done");
  });

  it("does not let a blank or non-Marmot `to` hide the bound group", async () => {
    const editMessage = vi.fn(async () => undefined);
    const cache = new Map([[HEX32("99"), { marmotAccountIdHex: HEX32("ab"), groupIdHex: HEX32("bb") }]]);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      sentTargetFor: (id) => cache.get(id),
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });
    const bound = { currentChannelId: HEX32("cc") };

    for (const to of ["", "   "]) {
      const crossConversation = await adapter.handleAction!(
        editCtx({ messageId: HEX32("99"), message: "x", to }, bound),
      );
      expect(resultError(crossConversation)).toMatch(/different conversation/);
    }
    const notMarmot = await adapter.handleAction!(
      editCtx({ messageId: HEX32("99"), message: "x", to: "telegram:12345" }, bound),
    );
    expect(resultError(notMarmot)).toMatch(/not a Marmot conversation/);
    expect(editMessage).not.toHaveBeenCalled();

    const blankOnCacheMiss = await adapter.handleAction!(
      editCtx({ messageId: HEX32("98"), message: "status: done", to: "" }, bound),
    );
    expect(resultOk(blankOnCacheMiss)).toBe(true);
    expect(editMessage).toHaveBeenCalledWith(HEX32("aa"), HEX32("cc"), HEX32("98"), "status: done");
  });

  it("edits a cached message when it matches the authorized target", async () => {
    const editMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      sentTargetFor: () => ({ marmotAccountIdHex: HEX32("ab"), groupIdHex: HEX32("cc") }),
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      editCtx({ messageId: HEX32("99"), message: "x", to: `marmot:${HEX32("cc").toUpperCase()}` }),
    );

    expect(editMessage).toHaveBeenCalledWith(HEX32("ab"), HEX32("cc"), HEX32("99"), "x");
    expect(resultOk(result)).toBe(true);
  });

  it("edits in the current conversation on a cache miss", async () => {
    const editMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const result = await adapter.handleAction!(
      editCtx(
        { messageId: HEX32("99"), text: "status: step 2" },
        { currentMessagingTarget: `marmot:${HEX32("cc")}` },
      ),
    );

    expect(editMessage).toHaveBeenCalledWith(HEX32("aa"), HEX32("cc"), HEX32("99"), "status: step 2");
    expect(resultOk(result)).toBe(true);
  });

  it("requires a message id, replacement text and a group before editing", async () => {
    const editMessage = vi.fn(async () => undefined);
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({ editMessage }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const noId = await adapter.handleAction!(editCtx({ message: "x", to: HEX32("cc") }));
    expect(resultError(noId)).toMatch(/messageId required/);
    const noText = await adapter.handleAction!(editCtx({ messageId: HEX32("99"), to: HEX32("cc") }));
    expect(resultError(noText)).toMatch(/message required/);
    const noGroup = await adapter.handleAction!(editCtx({ messageId: HEX32("99"), message: "x" }));
    expect(resultError(noGroup)).toMatch(/could not resolve group/);
    expect(editMessage).not.toHaveBeenCalled();
  });

  it("explains a refused edit", async () => {
    const refusals: Record<string, AgentControlError> = {
      [HEX32("01")]: new AgentControlError("refused", { code: "invalid_edit_target" }),
    };
    const adapter = createMarmotMessageActionAdapter({
      deleteByMessageId: async () => false,
      resolveTarget: async () => ({
        client: messageActionClient({
          editMessage: async (_account, _group, id) => {
            throw refusals[id];
          },
        }),
        marmotAccountIdHex: HEX32("aa"),
      }),
    });

    const refused = await adapter.handleAction!(
      editCtx({ messageId: HEX32("01"), message: "x", to: HEX32("cc") }),
    );
    expect(resultOk(refused)).toBe(false);
    expect(resultError(refused)).toMatch(/this agent sent/);
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

    const ctx = { ...deleteCtx({ messageId: HEX32("99") }), action: "pin" } as ChannelMessageActionContext;
    const result = await adapter.handleAction!(ctx);
    expect(resultOk(result)).toBe(false);
    expect(resultError(result)).toMatch(/unsupported action/);
  });
});
