import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";

import type { ResolvedMarmotAccount } from "../src/config.js";
import { startMarmotGatewayAccount } from "../src/gateway.js";
import {
  resetMarmotInboundAccountsForTests,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";

const syncCalls: Array<{ channelAccountId?: string | null }> = [];
const statusPatches: Array<Record<string, unknown>> = [];
let lifecycleStarts = 0;

vi.mock("openclaw/plugin-sdk/channel-lifecycle", () => ({
  createAccountStatusSink: ({ setStatus }: { setStatus: (next: unknown) => void }) => {
    return (patch: Record<string, unknown>) => {
      statusPatches.push(patch);
      setStatus(patch);
    };
  },
  runPassiveAccountLifecycle: async (options: {
    start: () => Promise<() => void>;
    stop: (stopInbound: () => void) => void | Promise<void>;
    onStop: () => void | Promise<void>;
  }) => {
    lifecycleStarts += 1;
    const stopInbound = await options.start();
    await options.stop(stopInbound);
    await options.onStop();
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

function account(overrides: Partial<ResolvedMarmotAccount> = {}): ResolvedMarmotAccount {
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

function gatewayContext(
  resolved: ResolvedMarmotAccount,
  options: { accountId?: string; includeRuntime?: boolean } = {},
): ChannelGatewayContext<ResolvedMarmotAccount> {
  const accountId = options.accountId ?? resolved.accountId ?? "default";
  return {
    cfg: { channels: { marmot: { accounts: { [accountId]: {} } } } },
    accountId,
    account: resolved,
    runtime: {} as never,
    abortSignal: AbortSignal.timeout(5_000),
    getStatus: () => ({ accountId, running: false, connected: false }),
    setStatus: () => {},
    channelRuntime:
      options.includeRuntime === false
        ? undefined
        : ({
            routing: {
              resolveAgentRoute: () => ({
                agentId: "main",
                accountId,
                sessionKey: "agent:main:marmot:group:test",
              }),
            },
            session: {
              resolveStorePath: () => "/tmp/openclaw-marmot-gateway-test",
              recordInboundSession: vi.fn(),
            },
            reply: {
              dispatchReplyWithBufferedBlockDispatcher: vi.fn(),
            },
          } as never),
    log: { info: () => {}, warn: () => {}, error: () => {} },
  };
}

afterEach(() => {
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
  syncCalls.length = 0;
  statusPatches.length = 0;
  lifecycleStarts = 0;
  vi.clearAllMocks();
});

describe("startMarmotGatewayAccount", () => {
  it("owns one passive inbound lifecycle for the configured channel account", async () => {
    await startMarmotGatewayAccount(gatewayContext(account(), { accountId: "acct-a" }));

    expect(syncCalls).toEqual([{ channelAccountId: "acct-a" }]);
    expect(lifecycleStarts).toBe(1);
    expect(statusPatches.some((patch) => patch.running === true)).toBe(true);
    expect(statusPatches.at(-1)).toMatchObject({ running: false, connected: false });
  });

  it("marks startup failure stopped instead of leaving the account running", async () => {
    await expect(
      startMarmotGatewayAccount(
        gatewayContext(account(), { accountId: "acct-a", includeRuntime: false }),
      ),
    ).rejects.toThrow(/channelRuntime is required/);

    expect(lifecycleStarts).toBe(0);
    expect(statusPatches.at(-1)).toMatchObject({
      running: false,
      connected: false,
      lastError: "inbound startup failed",
    });
  });
});
