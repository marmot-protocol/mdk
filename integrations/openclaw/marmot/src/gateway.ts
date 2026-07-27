// Marmot channel gateway lifecycle: owns the wn-agent inbound subscription per
// OpenClaw channel account via `gateway.startAccount`.

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-runtime";
import { enqueueSystemEvent } from "openclaw/plugin-sdk/channel-runtime";
import {
  createAccountStatusSink,
  runPassiveAccountLifecycle,
} from "openclaw/plugin-sdk/channel-lifecycle";
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

/** Resolve the configured default agent's display name for onboarding prompts. */
function resolveConfiguredAgentName(cfg: unknown): string | null {
  const agents = (cfg as { agents?: { list?: Array<{ name?: string; default?: boolean }> } })
    .agents;
  const agentList = agents?.list ?? [];
  return agentList.find((entry) => entry.default)?.name ?? agentList[0]?.name ?? null;
}

/** Start the passive inbound subscription for one Marmot channel account. */
export async function startMarmotGatewayAccount(
  ctx: ChannelGatewayContext<ResolvedMarmotAccount>,
): Promise<void> {
  const account = ctx.account;
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
  const markStopped = () => {
    statusSink({
      running: false,
      connected: false,
      lastStopAt: Date.now(),
    });
  };

  markRunning({ connected: false });
  ctx.log?.info?.("marmot: starting inbound subscription");

  const api: InboundPluginApi = {
    config: ctx.cfg,
    logger: {
      info: (message) => ctx.log?.info?.(message),
      warn: (message) => ctx.log?.warn?.(message),
    },
  };
  await syncMarmotAllowlist(api, { channelAccountId: ctx.accountId });

  const configuredAgentName = resolveConfiguredAgentName(ctx.cfg);
  const mentionPatterns = [...account.mentionPatterns, configuredAgentName].filter(
    (pattern): pattern is string => typeof pattern === "string" && pattern.trim().length > 0,
  );
  const channelRuntime = ctx.channelRuntime as unknown as OpenClawChannelRuntime | undefined;
  if (!channelRuntime) {
    throw new Error("marmot: channelRuntime is required for inbound agent dispatch");
  }

  const dispatch = createMarmotInboundDispatcher({
    cfg: ctx.cfg,
    runtimeChannel: channelRuntime,
    client: clientForAccount(account),
    channelAccountId: account.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
    streamMode: account.streamMode,
    blockStreaming: account.blockStreaming,
    quicCandidates: account.quicCandidates,
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
          statusSink({
            running: true,
            ...patch,
          });
        },
      }),
    stop: async (stopInbound) => {
      stopInbound?.();
    },
    onStop: () => {
      markStopped();
    },
  });
}
