import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";

import type { ResolvedMarmotAccount } from "../src/config.js";
import {
  allowlistRetryDelayMs,
  resetMarmotGatewayRecoveryForTests,
  startMarmotGatewayAccount,
  MARMOT_ALLOWLIST_RETRY_MAX_MS,
} from "../src/gateway.js";
import {
  resetMarmotInboundAccountsForTests,
  type InboundPluginApi,
  type MarmotAllowlistSyncResult,
} from "../src/inbound-runtime.js";
import {
  markMarmotInboundReady,
  markMarmotInboundStarting,
  marmotInboundRuntimeSnapshot,
  MARMOT_ALLOWLIST_SYNC_FAILED,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const syncCalls: Array<{ channelAccountId?: string | null }> = [];
const statusPatches: Array<Record<string, unknown>> = [];
let lifecycleStarts = 0;
const lifecycleByAccount = new Map<
  string,
  { started: Promise<void>; stop: () => Promise<void> }
>();

vi.mock("openclaw/plugin-sdk/channel-lifecycle", () => ({
  createAccountStatusSink: ({ setStatus }: { setStatus: (next: unknown) => void }) => {
    return (patch: Record<string, unknown>) => {
      statusPatches.push(patch);
      setStatus(patch);
    };
  },
  runPassiveAccountLifecycle: async (options: {
    abortSignal?: AbortSignal;
    start: () => Promise<() => void>;
    stop: (stopInbound: () => void) => void | Promise<void>;
    onStop: () => void | Promise<void>;
  }) => {
    lifecycleStarts += 1;
    let resolveStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      resolveStarted = resolve;
    });
    let resolveStopped!: () => void;
    const stopped = new Promise<void>((resolve) => {
      resolveStopped = resolve;
    });
    const accountId =
      [...statusPatches]
        .reverse()
        .find((patch) => typeof patch.accountId === "string")?.accountId ??
      `lifecycle-${lifecycleStarts}`;
    lifecycleByAccount.set(String(accountId), {
      started,
      stop: async () => {
        resolveStopped();
      },
    });
    const stopInbound = await options.start();
    resolveStarted();
    await Promise.race([
      stopped,
      options.abortSignal
        ? new Promise<void>((resolve) => {
            if (options.abortSignal!.aborted) {
              resolve();
              return;
            }
            options.abortSignal!.addEventListener("abort", () => resolve(), { once: true });
          })
        : stopped,
    ]);
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
      return { state: "unmanaged" } satisfies MarmotAllowlistSyncResult;
    }),
    startMarmotInbound: vi.fn((_api, _dispatch, options: { channelAccountId?: string | null }) => {
      const accountId = options.channelAccountId ?? "default";
      markMarmotInboundStarting(accountId);
      queueMicrotask(() => {
        markMarmotInboundReady(accountId);
      });
      return () => {};
    }),
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
  options: { accountId?: string; includeRuntime?: boolean; abortSignal?: AbortSignal } = {},
): ChannelGatewayContext<ResolvedMarmotAccount> {
  const accountId = options.accountId ?? resolved.accountId ?? "default";
  return {
    cfg: { channels: { marmot: { accounts: { [accountId]: {} } } } },
    accountId,
    account: resolved,
    runtime: {} as never,
    abortSignal: options.abortSignal ?? new AbortController().signal,
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

async function waitForLifecycle(accountId: string): Promise<{ stop: () => Promise<void> }> {
  const startedAt = Date.now();
  while (!lifecycleByAccount.has(accountId)) {
    if (Date.now() - startedAt > 1000) {
      throw new Error(`lifecycle for ${accountId} did not start`);
    }
    await Promise.resolve();
  }
  const handle = lifecycleByAccount.get(accountId)!;
  await handle.started;
  return handle;
}

afterEach(async () => {
  for (const handle of lifecycleByAccount.values()) {
    await handle.stop();
  }
  lifecycleByAccount.clear();
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
  resetMarmotGatewayRecoveryForTests();
  syncCalls.length = 0;
  statusPatches.length = 0;
  lifecycleStarts = 0;
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("startMarmotGatewayAccount", () => {
  it("owns one passive inbound lifecycle for the configured channel account", async () => {
    const running = startMarmotGatewayAccount(gatewayContext(account(), { accountId: "acct-a" }));
    const lifecycle = await waitForLifecycle("acct-a");

    expect(syncCalls).toEqual([{ channelAccountId: "acct-a" }]);
    expect(lifecycleStarts).toBe(1);
    expect(statusPatches.some((patch) => patch.running === true)).toBe(true);

    await lifecycle.stop();
    await running;
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

  it("keeps ack-after-sync-failure degraded and recovers without restarting inbound", async () => {
    const { syncMarmotAllowlist, startMarmotInbound } = await import("../src/inbound-runtime.js");
    let inboundStarts = 0;
    const outcomes: MarmotAllowlistSyncResult[] = [
      { state: "failed", reason: "unverified" },
      { state: "reconciled" },
    ];
    vi.mocked(syncMarmotAllowlist).mockImplementation(async (_api, options = {}) => {
      syncCalls.push(options);
      return outcomes[Math.min(syncCalls.length - 1, outcomes.length - 1)]!;
    });
    vi.mocked(startMarmotInbound).mockImplementation((_api, _dispatch, options) => {
      inboundStarts += 1;
      const accountId = options?.channelAccountId ?? "default";
      markMarmotInboundStarting(accountId);
      queueMicrotask(() => {
        markMarmotInboundReady(accountId);
      });
      return () => {};
    });

    const delays: number[] = [];
    const running = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"] }), { accountId: "work" }),
      {
        random: () => 0,
        delay: async (ms) => {
          delays.push(ms);
        },
      },
    );

    const lifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
        connected: true,
        lastError: null,
      });
    });
    expect(marmotInboundRuntimeSnapshot("work").lastError).not.toBeUndefined();
    expect(inboundStarts).toBe(1);
    expect(syncCalls.length).toBeGreaterThanOrEqual(2);
    expect(delays[0]).toBe(allowlistRetryDelayMs(0, () => 0));
    expect(delays[0]).toBeLessThanOrEqual(MARMOT_ALLOWLIST_RETRY_MAX_MS);

    await lifecycle.stop();
    await running;
  });

  it("does not mark healthy when policy recovers while inbound is down", async () => {
    const { syncMarmotAllowlist, startMarmotInbound } = await import("../src/inbound-runtime.js");
    const outcomes: MarmotAllowlistSyncResult[] = [
      { state: "failed", reason: "control" },
      { state: "reconciled" },
    ];
    vi.mocked(syncMarmotAllowlist).mockImplementation(async (_api, options = {}) => {
      syncCalls.push(options);
      return outcomes[Math.min(syncCalls.length - 1, outcomes.length - 1)]!;
    });
    vi.mocked(startMarmotInbound).mockImplementation((_api, _dispatch, options) => {
      markMarmotInboundStarting(options?.channelAccountId ?? "default");
      return () => {};
    });

    const running = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"] }), { accountId: "work" }),
      { random: () => 0, delay: async () => undefined },
    );
    const lifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(syncCalls.length).toBeGreaterThanOrEqual(2);
    });
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      connected: false,
      lastError: null,
    });

    await lifecycle.stop();
    await running;
  });

  it("cancels a pending retry on abort and does not publish a later healthy patch", async () => {
    const { syncMarmotAllowlist } = await import("../src/inbound-runtime.js");
    vi.mocked(syncMarmotAllowlist).mockImplementation(async (_api, options = {}) => {
      syncCalls.push(options);
      return { state: "failed", reason: "control" };
    });
    const abort = new AbortController();
    let resumeRetry: (() => void) | undefined;
    const running = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"] }), { accountId: "work", abortSignal: abort.signal }),
      {
        random: () => 0,
        delay: () =>
          new Promise<void>((resolve) => {
            resumeRetry = resolve;
          }),
      },
    );
    const lifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(syncCalls.length).toBe(1);
      expect(marmotInboundRuntimeSnapshot("work").lastError).toBe(MARMOT_ALLOWLIST_SYNC_FAILED);
    });
    abort.abort();
    await lifecycle.stop();
    await running;
    const syncsAfterStop = syncCalls.length;
    resumeRetry?.();
    await Promise.resolve();
    expect(syncCalls.length).toBe(syncsAfterStop);
    expect(statusPatches.at(-1)).toMatchObject({ connected: false });
  });

  it("keeps two channel accounts isolated across failure, recovery, and stop", async () => {
    const { syncMarmotAllowlist, startMarmotInbound } = await import("../src/inbound-runtime.js");
    const next = new Map<string, MarmotAllowlistSyncResult[]>([
      ["alpha", [{ state: "failed", reason: "unverified" }, { state: "reconciled" }]],
      ["beta", [{ state: "reconciled" }]],
    ]);
    vi.mocked(syncMarmotAllowlist).mockImplementation(async (_api, options = {}) => {
      const accountId = options.channelAccountId ?? "default";
      syncCalls.push(options);
      const queue = next.get(accountId) ?? [{ state: "unmanaged" }];
      return queue.length > 1 ? queue.shift()! : queue[0]!;
    });
    vi.mocked(startMarmotInbound).mockImplementation((_api, _dispatch, options) => {
      const accountId = options?.channelAccountId ?? "default";
      markMarmotInboundStarting(accountId);
      queueMicrotask(() => {
        markMarmotInboundReady(accountId);
      });
      return () => {};
    });

    const alphaRun = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"], accountId: "alpha" }), { accountId: "alpha" }),
      { random: () => 0, delay: async () => undefined },
    );
    const alpha = await waitForLifecycle("alpha");
    const betaRun = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["bb"], accountId: "beta" }), { accountId: "beta" }),
      { random: () => 0, delay: async () => undefined },
    );
    const beta = await waitForLifecycle("beta");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("alpha")).toMatchObject({
        connected: true,
        lastError: null,
      });
      expect(marmotInboundRuntimeSnapshot("beta")).toMatchObject({
        connected: true,
        lastError: null,
      });
    });
    await beta.stop();
    await betaRun;
    expect(marmotInboundRuntimeSnapshot("alpha")).toMatchObject({
      running: true,
      connected: true,
    });
    expect(marmotInboundRuntimeSnapshot("beta")).toMatchObject({
      running: false,
      connected: false,
    });
    await alpha.stop();
    await alphaRun;
  });
});
