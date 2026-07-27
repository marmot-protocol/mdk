import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";

import type { ResolvedMarmotAccount } from "../src/config.js";
import { startMarmotGatewayAccount } from "../src/gateway.js";
import {
  resetMarmotInboundAccountsForTests,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";

const syncCalls: { channelAccountId?: string | null }[] = [];
const lifecycleCalls: {
  start?: () => Promise<() => void>;
  stop?: (stopInbound?: () => void) => Promise<void>;
  onStop?: () => void;
}[] = [];
const statusPatches: Array<Record<string, unknown>> = [];

vi.mock("openclaw/plugin-sdk/channel-lifecycle", () => ({
  createAccountStatusSink: ({ setStatus }: { setStatus: (next: unknown) => void }) => {
    return (patch: Record<string, unknown>) => {
      statusPatches.push(patch);
      setStatus(patch);
    };
  },
  runPassiveAccountLifecycle: async (opts: {
    start: () => Promise<() => void>;
    stop: (stopInbound?: () => void) => Promise<void>;
    onStop: () => void;
  }) => {
    lifecycleCalls.push(opts);
    const stopInbound = await opts.start();
    await opts.stop(stopInbound);
    opts.onStop();
  },
}));

vi.mock("../src/inbound-runtime.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/inbound-runtime.js")>();
  return {
    ...actual,
    syncMarmotAllowlist: vi.fn(async (_api: InboundPluginApi, options = {}) => {
      syncCalls.push(options);
    }),
    startMarmotInbound: vi.fn(() => () => {}),
  };
});

function baseAccount(overrides: Partial<ResolvedMarmotAccount> = {}): ResolvedMarmotAccount {
  return {
    accountId: "default",
    socketPath: "/tmp/marmot.sock",
    streamMode: "off",
    blockStreaming: false,
    quicCandidates: [],
    groupActivation: "always",
    mentionPatterns: [],
    allowFrom: [],
    profileNameOnboarding: false,
    profileOnboardingStatePath: "/tmp/onboarding.json",
    debounceMs: 0,
    dmPolicy: "allowlist",
    ...overrides,
  };
}

function gatewayCtx(
  account: ResolvedMarmotAccount,
  accountId = account.accountId ?? "default",
): ChannelGatewayContext<ResolvedMarmotAccount> {
  return {
    cfg: { channels: { marmot: { accounts: { [accountId]: { socketPath: account.socketPath } } } } },
    accountId,
    account,
    runtime: {} as never,
    abortSignal: AbortSignal.timeout(5_000),
    getStatus: () => ({ accountId, running: false, connected: false }),
    setStatus: () => {},
    channelRuntime: {
      routing: { resolveAgentRoute: () => ({ agentId: "main", accountId, sessionKey: "sk" }) },
      runtimeContexts: {},
    } as never,
    log: { info: () => {}, warn: () => {}, error: () => {} },
  };
}

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
  resetMarmotInboundAccountsForTests();
  syncCalls.length = 0;
  lifecycleCalls.length = 0;
  statusPatches.length = 0;
  vi.clearAllMocks();
});

describe("startMarmotGatewayAccount", () => {
  it("awaits account-scoped allowlist sync before starting inbound", async () => {
    const account = baseAccount({ allowFrom: ["aa".repeat(32)] });
    await startMarmotGatewayAccount(gatewayCtx(account, "acct-a"));
    expect(syncCalls).toEqual([{ channelAccountId: "acct-a" }]);
    const inbound = await import("../src/inbound-runtime.js");
    expect(inbound.startMarmotInbound).toHaveBeenCalled();
  });

  it("marks running then stopped across the passive lifecycle", async () => {
    const account = baseAccount();
    await startMarmotGatewayAccount(gatewayCtx(account));
    expect(statusPatches.some((patch) => patch.running === true)).toBe(true);
    expect(statusPatches.at(-1)).toMatchObject({ running: false, connected: false });
    expect(lifecycleCalls).toHaveLength(1);
  });

  it("isolates two account starts without sharing lifecycle state", async () => {
    const accountA = baseAccount({ accountId: "acct-a", socketPath: "/tmp/a.sock" });
    const accountB = baseAccount({ accountId: "acct-b", socketPath: "/tmp/b.sock" });
    await startMarmotGatewayAccount(gatewayCtx(accountA, "acct-a"));
    const firstLifecycleCount = lifecycleCalls.length;
    await startMarmotGatewayAccount(gatewayCtx(accountB, "acct-b"));
    expect(syncCalls).toEqual([
      { channelAccountId: "acct-a" },
      { channelAccountId: "acct-b" },
    ]);
    expect(lifecycleCalls.length).toBe(firstLifecycleCount + 1);
  });
});
