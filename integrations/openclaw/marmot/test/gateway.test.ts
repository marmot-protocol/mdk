import { getEventListeners } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";

import type { MarmotAgentControlClient } from "../src/client.js";
import type { ResolvedMarmotAccount } from "../src/config.js";
import {
  allowlistRetryDelayMs,
  resetMarmotGatewayRecoveryForTests,
  startMarmotGatewayAccount,
  MARMOT_ALLOWLIST_RETRY_MAX_MS,
} from "../src/gateway.js";
import {
  resetMarmotInboundAccountsForTests,
  startMarmotInbound as startMarmotInboundExport,
  type InboundPluginApi,
  type MarmotAllowlistSyncResult,
  type SyncAllowlistOptions,
} from "../src/inbound-runtime.js";
import {
  markMarmotInboundReady,
  markMarmotInboundStarting,
  marmotInboundRuntimeSnapshot,
  marmotSenderAuthorizerLifecycle,
  MARMOT_ALLOWLIST_SYNC_FAILED,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";
import type { MarmotSenderAuthorizer } from "../src/sender-policy.js";

const syncCalls: Array<{ channelAccountId?: string | null }> = [];
/** Abort signals handed to each `syncMarmotAllowlist` call, in call order. */
const syncSignals: Array<AbortSignal | undefined> = [];
const statusPatches: Array<Record<string, unknown> & { subscribeCalls?: number }> = [];
let recordedSubscribeCalls = 0;
let lifecycleStarts = 0;
const lifecycleByAccount = new Map<
  string,
  { started: Promise<void>; stop: () => Promise<void> }
>();

vi.mock("openclaw/plugin-sdk/channel-lifecycle", () => ({
  createAccountStatusSink: ({ setStatus }: { setStatus: (next: unknown) => void }) => {
    return (patch: Record<string, unknown>) => {
      statusPatches.push({ ...patch, subscribeCalls: recordedSubscribeCalls });
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

/** Records a sync call in the shape assertions use, plus its abort signal. */
function recordSyncCall(options: SyncAllowlistOptions = {}): void {
  syncCalls.push({ channelAccountId: options.channelAccountId });
  syncSignals.push(options.signal);
}

async function defaultSyncMarmotAllowlist(
  _api: InboundPluginApi,
  options: SyncAllowlistOptions = {},
): Promise<MarmotAllowlistSyncResult> {
  recordSyncCall(options);
  return { state: "unmanaged" };
}

function defaultStartMarmotInbound(
  _api: unknown,
  _dispatch: unknown,
  options?: { channelAccountId?: string | null },
): () => void {
  const accountId = options?.channelAccountId ?? "default";
  markMarmotInboundStarting(accountId);
  queueMicrotask(() => {
    markMarmotInboundReady(accountId);
  });
  return () => {};
}

const { inboundRuntimeActual } = vi.hoisted(() => ({
  inboundRuntimeActual: {} as {
    startMarmotInbound?: typeof startMarmotInboundExport;
  },
}));

vi.mock("../src/inbound-runtime.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/inbound-runtime.js")>();
  inboundRuntimeActual.startMarmotInbound = actual.startMarmotInbound;
  return {
    ...actual,
    syncMarmotAllowlist: vi.fn(defaultSyncMarmotAllowlist),
    startMarmotInbound: vi.fn(defaultStartMarmotInbound),
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
    senderPolicy: { state: "allow_all", allowedUsers: [], allowedUserCount: 0 },
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
  syncSignals.length = 0;
  statusPatches.length = 0;
  recordedSubscribeCalls = 0;
  lifecycleStarts = 0;
  vi.clearAllMocks();
  // `clearAllMocks` clears calls but keeps implementations, so a per-test
  // override would otherwise decide the behaviour of every later test.
  const runtime = await import("../src/inbound-runtime.js");
  vi.mocked(runtime.syncMarmotAllowlist).mockImplementation(defaultSyncMarmotAllowlist);
  vi.mocked(runtime.startMarmotInbound).mockImplementation(defaultStartMarmotInbound);
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
      recordSyncCall(options);
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
      recordSyncCall(options);
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
      recordSyncCall(options);
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
      recordSyncCall(options);
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

  it("ignores a replaced generation's late accountList failure", async () => {
    const realStart = inboundRuntimeActual.startMarmotInbound;
    if (!realStart) {
      throw new Error("expected unmocked startMarmotInbound");
    }
    const hex = (byte: string) => byte.repeat(32);
    let rejectOld!: (error: Error) => void;
    const oldAccountList = new Promise<never>((_resolve, reject) => {
      rejectOld = reject;
    });
    let replacementSubscribes = 0;
    const startWithClient =
      (client: MarmotAgentControlClient): typeof realStart =>
      (api, dispatch, options = {}) =>
        realStart(api, dispatch, {
          ...options,
          clientFactory: () => client,
        });

    const abortOld = new AbortController();
    const oldRun = startMarmotGatewayAccount(
      gatewayContext(account(), { accountId: "work", abortSignal: abortOld.signal }),
      {
        startInbound: startWithClient({
          async accountList() {
            return oldAccountList;
          },
          async *subscribeInbound() {
            throw new Error("old generation must not subscribe");
          },
        } as unknown as MarmotAgentControlClient),
      },
    );
    const oldLifecycle = await waitForLifecycle("work");
    abortOld.abort();
    await oldLifecycle.stop();
    await oldRun;

    lifecycleByAccount.delete("work");
    const abortReplacement = new AbortController();
    const replacementRun = startMarmotGatewayAccount(
      gatewayContext(account(), { accountId: "work", abortSignal: abortReplacement.signal }),
      {
        startInbound: startWithClient({
          async accountList() {
            return {
              type: "account_list",
              accounts: [{ account_id_hex: hex("aa"), label: "agent", local_signing: true }],
            };
          },
          async *subscribeInbound(
            _filter?: unknown,
            _signal?: AbortSignal,
            hooks?: { onReady?: () => void },
          ) {
            replacementSubscribes += 1;
            hooks?.onReady?.();
            await new Promise<void>(() => undefined);
          },
        } as unknown as MarmotAgentControlClient),
      },
    );
    const replacement = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
        running: true,
        connected: true,
      });
    });
    const hostAfterAck = statusPatches.at(-1);
    expect(hostAfterAck).toMatchObject({ running: true, connected: true });

    rejectOld(new Error("secret stale account lookup"));
    await Promise.resolve();
    await Promise.resolve();

    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
    expect(statusPatches.at(-1)).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
    expect(JSON.stringify(statusPatches)).not.toContain("secret stale");

    let extraSubscribes = 0;
    realStart(
      {
        config: { channels: { marmot: { profileNameOnboarding: false } } },
        logger: { info: () => {}, warn: () => {} },
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
            async *subscribeInbound() {
              extraSubscribes += 1;
            },
          }) as unknown as MarmotAgentControlClient,
      },
    );
    await Promise.resolve();
    expect(replacementSubscribes).toBe(1);
    expect(extraSubscribes).toBe(0);

    abortReplacement.abort();
    await replacement.stop();
    await replacementRun;
  });

  it("does not let a stale lifecycle stop overwrite a healthy replacement", async () => {
    const abortOld = new AbortController();
    const oldRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortOld.signal,
      }),
    );
    const oldLifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
        running: true,
        connected: true,
      });
    });

    lifecycleByAccount.delete("work");
    const abortReplacement = new AbortController();
    const replacementRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortReplacement.signal,
      }),
    );
    const replacement = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
        running: true,
        connected: true,
      });
    });
    expect(marmotSenderAuthorizerLifecycle("work")).toBe("active");

    await oldLifecycle.stop();
    await oldRun;
    expect(marmotSenderAuthorizerLifecycle("work")).toBe("active");
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });

    abortReplacement.abort();
    await replacement.stop();
    await replacementRun;
  });

  /**
   * Starts a generation whose allowlist sync stays in flight until released, so
   * a replacement can be started against a genuinely unsettled predecessor.
   */
  function startStalledGeneration(accountId: string): {
    run: Promise<void>;
    abort: AbortController;
    signal: () => AbortSignal | undefined;
    dispatched: Promise<void>;
    release: (result: MarmotAllowlistSyncResult) => void;
  } {
    let markDispatched!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      markDispatched = resolve;
    });
    let release!: (result: MarmotAllowlistSyncResult) => void;
    const stalled = new Promise<MarmotAllowlistSyncResult>((resolve) => {
      release = resolve;
    });
    let signal: AbortSignal | undefined;
    const abort = new AbortController();
    const run = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId,
        abortSignal: abort.signal,
      }),
      {
        syncAllowlist: async (_api, options = {}) => {
          signal = options.signal;
          markDispatched();
          return stalled;
        },
      },
    );
    return { run, abort, signal: () => signal, dispatched, release };
  }

  it("aborts a superseded allowlist sync before the replacement reconciles", async () => {
    const old = startStalledGeneration("work");
    // The predecessor must genuinely own an in-flight sync, or this proves
    // nothing about the handover.
    await old.dispatched;
    expect(old.signal()?.aborted).toBe(false);

    lifecycleByAccount.delete("work");
    let predecessorStoppedFirst: boolean | undefined;
    const abortReplacement = new AbortController();
    const replacementRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortReplacement.signal,
      }),
      {
        syncAllowlist: async () => {
          predecessorStoppedFirst = old.signal()?.aborted;
          return { state: "unmanaged" };
        },
      },
    );

    // Liveness: reaching the passive lifecycle at all means this generation did
    // not block on a predecessor that has not settled.
    const replacement = await waitForLifecycle("work");
    // Safety: reconciliation is a non-atomic read-modify-write, so the
    // predecessor must stop issuing mutations before this generation starts
    // its own pass. Only the request already in flight can still be
    // outstanding, and that one is followed up when it settles.
    expect(predecessorStoppedFirst).toBe(true);
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({ running: true });

    old.release({ state: "unmanaged" });
    await old.run;
    abortReplacement.abort();
    await replacement.stop();
    await replacementRun;
    old.abort.abort();
  });

  it("reconciles again once a superseded sync finally settles", async () => {
    const old = startStalledGeneration("work");
    await old.dispatched;

    lifecycleByAccount.delete("work");
    const abortReplacement = new AbortController();
    const replacementRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortReplacement.signal,
      }),
    );
    const replacement = await waitForLifecycle("work");

    // The replacement reconciled once. The predecessor used the hook, so it
    // contributes nothing to syncCalls.
    expect(syncCalls).toEqual([{ channelAccountId: "work" }]);

    // Aborting cannot recall the one request the predecessor had already
    // dispatched, so it can still land after this generation read the allowlist
    // back. Settling must therefore trigger one more reconciliation.
    old.release({ state: "unmanaged" });
    await old.run;
    await vi.waitFor(() => {
      expect(syncCalls).toEqual([{ channelAccountId: "work" }, { channelAccountId: "work" }]);
    });

    abortReplacement.abort();
    await replacement.stop();
    await replacementRun;
    old.abort.abort();
  });

  it("inherits every unsettled writer across repeated handovers", async () => {
    const first = startStalledGeneration("work");
    await first.dispatched;
    const second = startStalledGeneration("work");
    await second.dispatched;
    expect(first.signal()?.aborted).toBe(true);

    const abortThird = new AbortController();
    const thirdRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortThird.signal,
      }),
    );
    const third = await waitForLifecycle("work");
    expect(second.signal()?.aborted).toBe(true);
    expect(syncCalls).toEqual([{ channelAccountId: "work" }]);

    // The oldest writer was abandoned by the first handover and must still be
    // followed up after the second one, or its late mutation outlives both.
    first.release({ state: "unmanaged" });
    await first.run;
    await vi.waitFor(() => {
      expect(syncCalls).toHaveLength(2);
    });

    // A writer that never settles must not gate the follow-up for one that did,
    // so each inherited writer gets its own pass.
    second.release({ state: "unmanaged" });
    await second.run;
    await vi.waitFor(() => {
      expect(syncCalls).toHaveLength(3);
    });

    abortThird.abort();
    await third.stop();
    await thirdRun;
    first.abort.abort();
    second.abort.abort();
  });

  it("retries a failed late-settlement follow-up until it reconciles", async () => {
    const old = startStalledGeneration("work");
    await old.dispatched;

    // Initial pass, then the follow-up triggered by the inherited writer
    // settling, then the scheduled retry of that follow-up.
    const outcomes: MarmotAllowlistSyncResult[] = [
      { state: "unmanaged" },
      { state: "failed", reason: "control" },
      { state: "reconciled" },
    ];
    const replacementSyncs: MarmotAllowlistSyncResult[] = [];
    const delays: number[] = [];
    const abortReplacement = new AbortController();
    const replacementRun = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"], marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortReplacement.signal,
      }),
      {
        random: () => 0,
        delay: async (ms) => {
          delays.push(ms);
        },
        syncAllowlist: async () => {
          const next = outcomes[Math.min(replacementSyncs.length, outcomes.length - 1)]!;
          replacementSyncs.push(next);
          return next;
        },
      },
    );
    const replacement = await waitForLifecycle("work");
    expect(replacementSyncs).toEqual([{ state: "unmanaged" }]);

    old.release({ state: "unmanaged" });
    await old.run;

    // The follow-up is the only pass that can correct the inherited writer's
    // late mutation, so a transient failure there must still converge.
    await vi.waitFor(() => {
      expect(replacementSyncs).toEqual([
        { state: "unmanaged" },
        { state: "failed", reason: "control" },
        { state: "reconciled" },
      ]);
    });
    expect(delays[0]).toBe(allowlistRetryDelayMs(0, () => 0));

    abortReplacement.abort();
    await replacement.stop();
    await replacementRun;
    old.abort.abort();
  });

  it("does not reconcile again when no superseded sync was in flight", async () => {
    const abortFirst = new AbortController();
    const firstRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortFirst.signal,
      }),
    );
    const first = await waitForLifecycle("work");
    expect(syncCalls).toEqual([{ channelAccountId: "work" }]);

    lifecycleByAccount.delete("work");
    const abortSecond = new AbortController();
    const secondRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortSecond.signal,
      }),
    );
    const second = await waitForLifecycle("work");

    // A settled predecessor owes its successor nothing, so the handover must not
    // cost an extra reconciliation pass.
    await vi.waitFor(() => {
      expect(syncCalls).toEqual([{ channelAccountId: "work" }, { channelAccountId: "work" }]);
    });
    expect(syncCalls).toHaveLength(2);

    abortFirst.abort();
    abortSecond.abort();
    await first.stop();
    await second.stop();
    await firstRun;
    await secondRun;
  });

  it("stops a generation's reconciliation when that generation is torn down", async () => {
    const abortFirst = new AbortController();
    const firstRun = startMarmotGatewayAccount(
      gatewayContext(account({ marmotAccountIdHex: "aa".repeat(32) }), {
        accountId: "work",
        abortSignal: abortFirst.signal,
      }),
    );
    const first = await waitForLifecycle("work");
    expect(syncSignals).toHaveLength(1);
    expect(syncSignals[0]?.aborted).toBe(false);

    abortFirst.abort();
    await first.stop();
    await firstRun;
    // A stopped generation must not leave a live writer behind on the lane.
    expect(syncSignals[0]?.aborted).toBe(true);
  });

  it("releases failed inbound attempts before retrying through the real runtime", async () => {
    const realStart = inboundRuntimeActual.startMarmotInbound;
    if (!realStart) {
      throw new Error("expected unmocked startMarmotInbound");
    }
    const hex = (byte: string) => byte.repeat(32);
    const allowed = hex("bb");
    const denied = hex("99");
    const abort = new AbortController();
    let constructionFailures = 0;
    let accountListFailures = 0;
    let subscribeCalls = 0;
    let mode: "construct" | "accountList" | "ready" = "construct";
    const startCounts: number[] = [];
    const admitted: string[] = [];
    const logs: string[] = [];
    let sharedAuthorizer: MarmotSenderAuthorizer | undefined;
    let pushEvent: ((event: Record<string, unknown>) => void) | undefined;

    const inboundMessage = (sender: string, messageByte: string, isSelf = false) => ({
      type: "inbound_message",
      account_id_hex: hex("aa"),
      group_id_hex: hex("cc"),
      mentions_self: true,
      message: {
        message_id_hex: hex(messageByte),
        sender: { account_id_hex: sender, display_name: "Peer", is_self: isSelf },
        text: "please help",
        recorded_at: 1_721_000_000,
        media: [],
      },
    });

    const ctx = gatewayContext(
      account({
        marmotAccountIdHex: hex("aa"),
        senderPolicy: { state: "allowlist", allowedUsers: [allowed], allowedUserCount: 1 },
      }),
      { accountId: "work", abortSignal: abort.signal },
    );
    ctx.log = {
      info: (message: string) => logs.push(message),
      warn: (message: string) => logs.push(message),
      error: (message: string) => logs.push(message),
    };

    const running = startMarmotGatewayAccount(ctx, {
      random: () => 0,
      delay: async () => undefined,
      startInbound: (api, _dispatch, options = {}) => {
        sharedAuthorizer = options.authorizer;
        const started = realStart(
          api,
          async (message) => {
            admitted.push(message.senderAccountIdHex);
            return true;
          },
          {
            ...options,
            clientFactory: () => {
              if (mode === "construct") {
                constructionFailures += 1;
                if (constructionFailures < 6) {
                  throw new Error("secret socket detail");
                }
                mode = "accountList";
              }
              return {
                async accountList() {
                  if (mode === "accountList") {
                    accountListFailures += 1;
                    if (accountListFailures < 6) {
                      throw new Error("secret account lookup");
                    }
                    mode = "ready";
                  }
                  return {
                    type: "account_list",
                    accounts: [{ account_id_hex: hex("aa"), label: "agent", local_signing: true }],
                  };
                },
                async *subscribeInbound(
                  _filter?: unknown,
                  signal?: AbortSignal,
                  hooks?: { onReady?: () => void },
                ) {
                  subscribeCalls += 1;
                  recordedSubscribeCalls = subscribeCalls;
                  hooks?.onReady?.();
                  const queued: Array<Record<string, unknown>> = [];
                  let notify: (() => void) | undefined;
                  pushEvent = (event) => {
                    queued.push(event);
                    notify?.();
                  };
                  while (!signal?.aborted) {
                    if (queued.length === 0) {
                      await new Promise<void>((resolve) => {
                        if (signal?.aborted) {
                          resolve();
                          return;
                        }
                        notify = resolve;
                        signal?.addEventListener("abort", () => resolve(), { once: true });
                      });
                    }
                    while (queued.length > 0) {
                      yield queued.shift() as never;
                    }
                  }
                },
              } as unknown as MarmotAgentControlClient;
            },
          },
        );
        startCounts.push(getEventListeners(options?.signal ?? abort.signal, "abort").length);
        return started;
      },
    });
    const lifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
        running: true,
        connected: true,
      });
    });
    expect(constructionFailures).toBe(6);
    expect(accountListFailures).toBe(6);
    expect(subscribeCalls).toBe(1);
    expect(Math.max(...startCounts)).toBeLessThanOrEqual(1);
    expect(
      statusPatches.some((patch) => patch.connected === true && patch.subscribeCalls === 0),
    ).toBe(false);
    expect(sharedAuthorizer?.lifecycle()).toBe("active");
    expect(
      sharedAuthorizer?.authorize({
        receivingAccountIdHex: hex("aa"),
        mappedSenderAccountIdHex: allowed,
        sender: { account_id_hex: allowed, is_self: false },
      }),
    ).toEqual({ outcome: "allow", reason: "allowlist" });
    expect(
      sharedAuthorizer?.authorize({
        receivingAccountIdHex: hex("aa"),
        mappedSenderAccountIdHex: denied,
        sender: { account_id_hex: denied, is_self: false },
      }),
    ).toEqual({ outcome: "deny", reason: "sender_not_allowed" });

    pushEvent?.(inboundMessage(denied, "d1"));
    await vi.waitFor(() => {
      expect(logs.some((line) => line.includes("reason=sender_not_allowed"))).toBe(true);
    });
    expect(admitted).toEqual([]);
    pushEvent?.(inboundMessage(allowed, "d2"));
    await vi.waitFor(() => {
      expect(admitted).toEqual([allowed]);
    });
    expect(logs.join("\n")).not.toContain(allowed);
    expect(logs.join("\n")).not.toContain(denied);

    sharedAuthorizer?.setLifecycle("replaced");
    expect(
      sharedAuthorizer?.authorize({
        receivingAccountIdHex: hex("aa"),
        mappedSenderAccountIdHex: allowed,
        sender: { account_id_hex: allowed, is_self: false },
      }),
    ).toEqual({ outcome: "deny", reason: "lifecycle_replaced" });

    const patchesAfterReady = statusPatches.length;
    abort.abort();
    await lifecycle.stop();
    await running;
    await Promise.resolve();
    expect(subscribeCalls).toBe(1);
    expect(admitted).toEqual([allowed]);
    expect(statusPatches.length).toBeGreaterThanOrEqual(patchesAfterReady);
    expect(statusPatches.at(-1)).toMatchObject({ running: false, connected: false });
    expect(JSON.stringify(statusPatches)).not.toContain("secret socket");
    expect(JSON.stringify(statusPatches)).not.toContain("secret account");
  });

  it("swallows unexpected retry continuation throws", async () => {
    const { syncMarmotAllowlist } = await import("../src/inbound-runtime.js");
    let calls = 0;
    vi.mocked(syncMarmotAllowlist).mockImplementation(async (_api, options = {}) => {
      recordSyncCall(options);
      calls += 1;
      if (calls === 1) {
        return { state: "failed", reason: "control" };
      }
      throw new Error("secret retry boom");
    });
    const rejections: unknown[] = [];
    const onUnhandled = (reason: unknown) => {
      rejections.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    const running = startMarmotGatewayAccount(
      gatewayContext(account({ allowFrom: ["aa"] }), { accountId: "work" }),
      { random: () => 0, delay: async () => undefined },
    );
    const lifecycle = await waitForLifecycle("work");
    await vi.waitFor(() => {
      expect(calls).toBeGreaterThanOrEqual(2);
    });
    await Promise.resolve();
    process.off("unhandledRejection", onUnhandled);
    expect(rejections).toEqual([]);
    await lifecycle.stop();
    await running;
  });
});
