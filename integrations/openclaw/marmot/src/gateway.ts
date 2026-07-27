// Marmot channel gateway lifecycle. OpenClaw starts one long-lived task per
// configured channel account; that task owns exactly one wn-agent subscription.

import {
  createAccountStatusSink,
  runPassiveAccountLifecycle,
} from "openclaw/plugin-sdk/channel-lifecycle";
import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";
import { enqueueSystemEvent } from "openclaw/plugin-sdk/channel-runtime";
import type { ChannelAccountSnapshot } from "openclaw/plugin-sdk/status-helpers";

import { clientForAccount, type ResolvedMarmotAccount } from "./config.js";
import { createMarmotInboundDispatcher, type OpenClawChannelRuntime } from "./dispatch.js";
import {
  startMarmotInbound,
  syncMarmotAllowlist,
  type InboundPluginApi,
  type MarmotAmbientSurfacer,
} from "./inbound-runtime.js";
import { DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID } from "./runtime-state.js";

function resolveConfiguredAgentName(cfg: unknown): string | null {
  const agents = (cfg as { agents?: { list?: Array<{ name?: string; default?: boolean }> } })
    .agents;
  const agentList = agents?.list ?? [];
  return agentList.find((entry) => entry.default)?.name ?? agentList[0]?.name ?? null;
}

/** Start and own the inbound subscription for one OpenClaw Marmot account. */
export async function startMarmotGatewayAccount(
  ctx: ChannelGatewayContext<ResolvedMarmotAccount>,
): Promise<void> {
  const statusSink = createAccountStatusSink({
    accountId: ctx.accountId,
    setStatus: ctx.setStatus,
  });
  const markRunning = (patch: Partial<ChannelAccountSnapshot> = {}) => {
    statusSink({
      running: true,
      connected: patch.connected ?? false,
      lastStartAt: patch.lastStartAt ?? Date.now(),
      lastStopAt: null,
      lastError: null,
      ...patch,
    });
  };
  const markStopped = (lastError: string | null = null) => {
    statusSink({
      running: false,
      connected: false,
      lastStopAt: Date.now(),
      lastError,
    });
  };

  markRunning();
  ctx.log?.info?.("marmot: starting inbound subscription");

  try {
    const api: InboundPluginApi = {
      config: ctx.cfg,
      logger: {
        info: (message) => ctx.log?.info?.(message),
        warn: (message) => ctx.log?.warn?.(message),
      },
    };
    await syncMarmotAllowlist(api, { channelAccountId: ctx.accountId });

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
      log: (message) => ctx.log?.info?.(message),
    });

    const surfaceAmbientEvent: MarmotAmbientSurfacer = ({ groupIdHex, text, contextKey }) => {
      const route = channelRuntime.routing.resolveAgentRoute({
        cfg: ctx.cfg,
        channel: "marmot",
        accountId: account.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
        peer: { kind: "group", id: groupIdHex },
      });
      enqueueSystemEvent(text, {
        sessionKey: route.sessionKey,
        contextKey: contextKey ?? null,
      });
    };

    await runPassiveAccountLifecycle({
      abortSignal: ctx.abortSignal,
      start: async () =>
        startMarmotInbound(api, dispatch, {
          signal: ctx.abortSignal,
          channelAccountId: ctx.accountId,
          configuredAgentName,
          surfaceAmbientEvent,
          invalidateGroupActivation: dispatch.invalidateGroupActivation,
          clearGroupActivationCache: dispatch.clearGroupActivationCache,
          statusSink: (patch) => {
            statusSink({ running: true, ...patch });
          },
        }),
      stop: (stopInbound) => {
        stopInbound();
      },
      onStop: () => {
        markStopped();
      },
    });
  } catch (error) {
    markStopped("inbound startup failed");
    ctx.log?.error?.("marmot: inbound startup failed");
    throw error;
  }
}
