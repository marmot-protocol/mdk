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

export interface MarmotGatewayAccountHooks {
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
  random?: () => number;
  syncAllowlist?: typeof syncMarmotAllowlist;
  startInbound?: typeof startMarmotInbound;
}

interface AccountRecoveryLane {
  generation: number;
  syncTail: Promise<void>;
  /**
   * Aborts the reconciliation owned by the generation that currently holds
   * `syncTail`, so a replacement can supersede it instead of waiting on it.
   */
  syncAbort: AbortController | null;
  /**
   * Generation whose `syncAllowlist` call is dispatched and unsettled, or null
   * when no call is outstanding. A successor reads this to learn whether it
   * inherited a writer that can still land a mutation after the handover.
   */
  syncInFlightGeneration: number | null;
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

function laneFor(accountId: string): AccountRecoveryLane {
  const existing = recoveryLanes.get(accountId);
  if (existing) {
    return existing;
  }
  const created: AccountRecoveryLane = {
    generation: 0,
    syncTail: Promise.resolve(),
    syncAbort: null,
    syncInFlightGeneration: null,
  };
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

  const abortController = new AbortController();
  const onHostAbort = (): void => {
    abortController.abort();
  };
  if (ctx.abortSignal.aborted) {
    abortController.abort();
  } else {
    ctx.abortSignal.addEventListener("abort", onHostAbort, { once: true });
  }

  const lane = laneFor(ctx.accountId);
  const generation = lane.generation + 1;
  lane.generation = generation;

  // Reconciliation is a non-atomic read-modify-write over a shared account, so
  // two generations must never run it at once. Awaiting the predecessor is not
  // how to get that: its control calls carry no timeout, so a stalled one would
  // keep this generation from ever starting. Tell it to stop instead, then take
  // the lane. It stops at its next mutation boundary; anything it left pending
  // is covered by this generation's own pass, which reads the allowlist fresh
  // and reconciles the current desired set.
  const supersededSync = lane.syncInFlightGeneration !== null ? lane.syncTail : null;
  lane.syncAbort?.abort();
  const syncAbort = new AbortController();
  lane.syncAbort = syncAbort;
  lane.syncTail = Promise.resolve();

  let closed = false;
  let allowlistAttempt = 0;
  let allowlistRetryPending = false;
  let inboundAttempt = 0;
  let inboundRetrying = false;
  let inboundStop: () => void = () => {};
  let stoppedStatusGeneration: number | null = null;

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
      lane.syncInFlightGeneration = generation;
      try {
        result = await syncAllowlist(api, {
          channelAccountId: ctx.accountId,
          signal: syncAbort.signal,
        });
      } finally {
        // Clear only this generation's own marker. A superseded call settling
        // late must not report a successor's in-flight sync as finished.
        if (lane.syncInFlightGeneration === generation) {
          lane.syncInFlightGeneration = null;
        }
      }
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
    if (lane.syncAbort === syncAbort) {
      lane.syncAbort = null;
    }
    // This generation is done reconciling either way; stop its sync here rather
    // than through an `abortController` listener, which would outlive every
    // inbound retry and read as a leaked subscription.
    syncAbort.abort();
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

    // The superseded generation was told to stop, but the one request it had
    // already dispatched cannot be recalled, so it can still land after this
    // generation read the allowlist back. Reconcile once more when its call
    // finally settles, so a late write cannot outlive the handover. A
    // predecessor that never settles never triggers this, which is exactly why
    // this generation did not wait on it.
    if (supersededSync) {
      void supersededSync.then(() => {
        if (!isCurrent()) {
          return;
        }
        void enqueueSync().catch(() => undefined);
      });
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
        const ownedLane = lane.generation === generation;
        cancelRetries();
        if (ownedLane) {
          stoppedStatusGeneration = lane.generation;
        }
        stopInbound();
      },
      onStop: () => {
        if (
          stoppedStatusGeneration === null ||
          lane.generation !== stoppedStatusGeneration
        ) {
          return;
        }
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
