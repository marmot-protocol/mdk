// Marmot channel gateway lifecycle. OpenClaw starts one long-lived task per
// configured channel account; that task owns exactly one wn-agent subscription
// and serialized allowlist-reconciliation recovery for that account.

import {
  createAccountStatusSink,
  runPassiveAccountLifecycle,
} from "openclaw/plugin-sdk/channel-lifecycle";
import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-contract";

import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import { createMarmotInboundDispatcher, type OpenClawChannelRuntime } from "./dispatch.js";
import {
  startMarmotInbound,
  syncMarmotAllowlist,
  type InboundPluginApi,
  type MarmotAllowlistSyncResult,
} from "./inbound-runtime.js";
import {
  beginMarmotAccountLifecycle,
  DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
  markMarmotAllowlistSyncResult,
  markMarmotInboundStopped,
  markMarmotSenderAuthorizerLifecycle,
  markMarmotSenderPolicyResult,
  marmotInboundRuntimeSnapshot,
} from "./runtime-state.js";
import { createSenderAuthorizer } from "./sender-policy.js";

export const MARMOT_ALLOWLIST_RETRY_BASE_MS = 1_000;
export const MARMOT_ALLOWLIST_RETRY_MAX_MS = 30_000;
export const MARMOT_SUPERSEDED_SYNC_DRAIN_MS = 5_000;

export interface MarmotGatewayAccountHooks {
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
  /**
   * Bounds the wait on a superseded generation's allowlist sync. Separate from
   * `delay` so retry-backoff assertions are not perturbed by the drain timer.
   */
  drainDelay?: (ms: number, signal: AbortSignal) => Promise<void>;
  random?: () => number;
  syncAllowlist?: typeof syncMarmotAllowlist;
  startInbound?: typeof startMarmotInbound;
}

interface AccountRecoveryLane {
  generation: number;
  syncTail: Promise<void>;
}

const recoveryLanes = new Map<string, AccountRecoveryLane>();

export function resetMarmotGatewayRecoveryForTests(): void {
  recoveryLanes.clear();
}

function resolveConfiguredAgentName(cfg: unknown): string | null {
  const agents = (cfg as { agents?: { list?: Array<{ name?: string; default?: boolean }> } })
    .agents;
  const agentList = agents?.list ?? [];
  return agentList.find((entry) => entry.default)?.name ?? agentList[0]?.name ?? null;
}

function defaultDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function allowlistRetryDelayMs(attempt: number, random: () => number = Math.random): number {
  const exp = Math.min(
    MARMOT_ALLOWLIST_RETRY_MAX_MS,
    MARMOT_ALLOWLIST_RETRY_BASE_MS * 2 ** Math.max(0, attempt),
  );
  return Math.min(MARMOT_ALLOWLIST_RETRY_MAX_MS, exp * (0.5 + random() * 0.5));
}

/**
 * Wait for a superseded generation's allowlist sync before this generation
 * reconciles, but never wait on it forever.
 *
 * `lane.syncTail` serializes allowlist reconciliation per account so a stale
 * generation cannot race a replacement against the same wn-agent allowlist.
 * The tail can still be an unsettled control-socket call owned by a generation
 * that has already been superseded, and that generation's result is discarded
 * anyway. Bound the wait, then detach the stale tail so a replacement start is
 * not held behind a predecessor that never settles.
 */
async function drainSupersededSync(
  lane: AccountRecoveryLane,
  signal: AbortSignal,
  drainDelay: (ms: number, signal: AbortSignal) => Promise<void>,
  warn: (message: string) => void,
): Promise<void> {
  if (signal.aborted) {
    // Already shutting down: an aborted signal never fires `abort` again, so
    // arming the drain timer here could only stall an unwinding start.
    return;
  }
  const tail = lane.syncTail;
  let drained = false;
  const settled = tail.then(
    () => {
      drained = true;
    },
    () => {
      drained = true;
    },
  );
  const drainAbort = new AbortController();
  const cancelDrain = (): void => {
    drainAbort.abort();
  };
  signal.addEventListener("abort", cancelDrain, { once: true });
  try {
    await Promise.race([settled, drainDelay(MARMOT_SUPERSEDED_SYNC_DRAIN_MS, drainAbort.signal)]);
  } finally {
    drainAbort.abort();
    signal.removeEventListener("abort", cancelDrain);
  }
  if (drained) {
    return;
  }
  lane.syncTail = Promise.resolve();
  if (!signal.aborted) {
    warn("marmot: superseded allowlist sync did not settle; starting without it");
  }
}

function laneFor(accountId: string): AccountRecoveryLane {
  const existing = recoveryLanes.get(accountId);
  if (existing) {
    return existing;
  }
  const created = { generation: 0, syncTail: Promise.resolve() };
  recoveryLanes.set(accountId, created);
  return created;
}

/** Start and own the inbound subscription for one OpenClaw Marmot account. */
export async function startMarmotGatewayAccount(
  ctx: ChannelGatewayContext<ResolvedMarmotAccount>,
  hooks: MarmotGatewayAccountHooks = {},
): Promise<void> {
  const statusSink = createAccountStatusSink({
    accountId: ctx.accountId,
    setStatus: ctx.setStatus,
  });
  const delay = hooks.delay ?? defaultDelay;
  const drainDelay = hooks.drainDelay ?? defaultDelay;
  const random = hooks.random ?? Math.random;
  const syncAllowlist = hooks.syncAllowlist ?? syncMarmotAllowlist;
  const startInbound = hooks.startInbound ?? startMarmotInbound;
  const publishStatus = (): void => {
    statusSink(marmotInboundRuntimeSnapshot(ctx.accountId));
  };
  const markStartupFailed = (): void => {
    markMarmotInboundStopped(ctx.accountId);
    statusSink({
      ...marmotInboundRuntimeSnapshot(ctx.accountId),
      running: false,
      connected: false,
      lastStopAt: Date.now(),
      lastError: "inbound startup failed",
    });
  };

  beginMarmotAccountLifecycle(ctx.accountId);
  const authorizer = createSenderAuthorizer({ policy: ctx.account.senderPolicy });
  if (ctx.account.marmotAccountIdHex) {
    authorizer.bindReceivingAccount(ctx.account.marmotAccountIdHex);
  }
  markMarmotSenderPolicyResult(ctx.accountId, ctx.account.senderPolicy);
  publishStatus();
  ctx.log?.info?.("marmot: starting inbound subscription");

  const lane = laneFor(ctx.accountId);
  const generation = lane.generation + 1;
  lane.generation = generation;

  const abortController = new AbortController();
  const onHostAbort = (): void => {
    abortController.abort();
  };
  if (ctx.abortSignal.aborted) {
    abortController.abort();
  } else {
    ctx.abortSignal.addEventListener("abort", onHostAbort, { once: true });
  }

  await drainSupersededSync(lane, abortController.signal, drainDelay, (message) =>
    ctx.log?.warn?.(message),
  );

  let closed = false;
  let allowlistAttempt = 0;
  let allowlistRetryPending = false;
  let inboundAttempt = 0;
  let inboundRetrying = false;
  let inboundStop: () => void = () => {};

  const isCurrent = (): boolean =>
    !closed && lane.generation === generation && !abortController.signal.aborted;

  const applySyncResult = (result: MarmotAllowlistSyncResult): void => {
    if (!isCurrent()) {
      return;
    }
    markMarmotAllowlistSyncResult(ctx.accountId, result);
    publishStatus();
  };

  const enqueueSync = (): Promise<MarmotAllowlistSyncResult | null> => {
    let result: MarmotAllowlistSyncResult | null = null;
    const run = lane.syncTail.then(async () => {
      if (!isCurrent()) {
        return;
      }
      const api: InboundPluginApi = {
        config: ctx.cfg,
        logger: {
          info: (message) => ctx.log?.info?.(message),
          warn: (message) => ctx.log?.warn?.(message),
        },
      };
      result = await syncAllowlist(api, { channelAccountId: ctx.accountId });
      applySyncResult(result);
    });
    lane.syncTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run.then(() => result);
  };

  const scheduleAllowlistRetry = (): void => {
    if (!isCurrent() || allowlistRetryPending) {
      return;
    }
    allowlistRetryPending = true;
    const waitMs = allowlistRetryDelayMs(allowlistAttempt, random);
    allowlistAttempt += 1;
    void delay(waitMs, abortController.signal)
      .then(async () => {
        allowlistRetryPending = false;
        if (!isCurrent()) {
          return;
        }
        try {
          const result = await enqueueSync();
          if (result?.state === "failed") {
            scheduleAllowlistRetry();
          }
        } catch {
          // Typed sync results cannot throw; swallow unexpected hook failures
          // so a voided retry cannot become an unhandled rejection.
        }
      })
      .catch(() => {
        allowlistRetryPending = false;
      });
  };

  const cancelRetries = (): void => {
    closed = true;
    authorizer.setLifecycle("replaced");
    if (lane.generation === generation) {
      markMarmotSenderAuthorizerLifecycle(ctx.accountId, "replaced");
      lane.generation += 1;
    }
    abortController.abort();
    allowlistRetryPending = false;
  };

  try {
    const api: InboundPluginApi = {
      config: ctx.cfg,
      logger: {
        info: (message) => ctx.log?.info?.(message),
        warn: (message) => ctx.log?.warn?.(message),
      },
    };
    const first = await enqueueSync();
    if (!isCurrent()) {
      const ownsStatus = lane.generation === generation;
      cancelRetries();
      if (ownsStatus) {
        markMarmotInboundStopped(ctx.accountId);
        publishStatus();
      }
      return;
    }
    if (first?.state === "failed") {
      scheduleAllowlistRetry();
    }

    const channelRuntime = ctx.channelRuntime as unknown as OpenClawChannelRuntime | undefined;
    if (!channelRuntime) {
      throw new Error("marmot: channelRuntime is required for inbound agent dispatch");
    }

    const account = ctx.account;
    const configuredAgentName = resolveConfiguredAgentName(ctx.cfg);
    const mentionPatterns = [...account.mentionPatterns, configuredAgentName].filter(
      (pattern): pattern is string => typeof pattern === "string" && pattern.trim().length > 0,
    );
    const dispatch = createMarmotInboundDispatcher({
      cfg: ctx.cfg,
      runtimeChannel: channelRuntime,
      client: clientForAccount(account),
      channelAccountId: account.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
      groupActivation: account.groupActivation,
      mentionPatterns,
      authorizer,
      log: (message) => ctx.log?.info?.(message),
    });

    const startInboundOnce = (): void => {
      if (!isCurrent()) {
        return;
      }
      const previousStop = inboundStop;
      inboundStop = () => {};
      previousStop();
      inboundStop = startInbound(api, dispatch, {
        signal: abortController.signal,
        channelAccountId: ctx.accountId,
        configuredAgentName,
        authorizer,
        invalidateGroupActivation: dispatch.invalidateGroupActivation,
        clearGroupActivationCache: dispatch.clearGroupActivationCache,
        statusSink: () => {
          if (!isCurrent()) {
            return;
          }
          publishStatus();
        },
        onSetupFailed: () => {
          if (!isCurrent() || inboundRetrying) {
            return;
          }
          inboundRetrying = true;
          const waitMs = allowlistRetryDelayMs(inboundAttempt, random);
          inboundAttempt += 1;
          void delay(waitMs, abortController.signal)
            .then(() => {
              inboundRetrying = false;
              if (!isCurrent()) {
                return;
              }
              try {
                startInboundOnce();
              } catch {
                // Defense-in-depth: startMarmotInbound catches known setup
                // failures. Do not surface an injected throw as unhandled.
              }
            })
            .catch(() => {
              inboundRetrying = false;
            });
        },
      });
    };

    await runPassiveAccountLifecycle({
      abortSignal: ctx.abortSignal,
      start: async () => {
        startInboundOnce();
        return () => {
          inboundStop();
        };
      },
      stop: (stopInbound) => {
        cancelRetries();
        stopInbound();
      },
      onStop: () => {
        markMarmotInboundStopped(ctx.accountId);
        publishStatus();
      },
    });
  } catch (error) {
    cancelRetries();
    inboundStop();
    markStartupFailed();
    ctx.log?.error?.("marmot: inbound startup failed");
    throw error;
  } finally {
    ctx.abortSignal.removeEventListener("abort", onHostAbort);
    inboundStop();
  }
}
