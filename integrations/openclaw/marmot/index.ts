// OpenClaw plugin runtime entry. Registers the Marmot channel, syncs the
// welcomer allowlist, and starts the inbound subscription that drives the agent
// turn (modeled on the bundled Telegram channel). See README.md for setup.

import {
  defineChannelPluginEntry,
  type OpenClawPluginApi,
} from "openclaw/plugin-sdk/channel-core";

import {
  createMarmotChannelPlugin,
  MARMOT_CHANNEL_ID,
  resolveMarmotChannelAccount,
} from "./src/channel.js";
import { clientForAccount } from "./src/config.js";
import { createMarmotInboundDispatcher, type OpenClawChannelRuntime } from "./src/dispatch.js";
import {
  startMarmotInbound,
  syncMarmotAllowlist,
  type MarmotAmbientSurfacer,
} from "./src/inbound-runtime.js";
import { DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID } from "./src/runtime-state.js";

export default defineChannelPluginEntry({
  id: MARMOT_CHANNEL_ID,
  name: "Marmot",
  description: "End-to-end encrypted Marmot groups through the local dm-agent connector.",
  plugin: createMarmotChannelPlugin(),
  registerFull(api: OpenClawPluginApi) {
    api.logger.info(
      `marmot: registerFull invoked (registrationMode=${String(
        (api as { registrationMode?: unknown }).registrationMode ?? "unknown",
      )})`,
    );
    void (async () => {
      try {
        // Mirror configured dm.allowFrom welcomers into dm-agent before consuming
        // inbound, so the welcomer policy is in place when the agent goes live.
        // (syncMarmotAllowlist is self-guarded and never rejects.)
        await syncMarmotAllowlist(api);

        const resolved = resolveMarmotChannelAccount(api.config, null);

        // Inherit the configured OpenClaw agent name (if any): it seeds the
        // profile-name onboarding flow and, as a trigger phrase, lets the agent
        // recognize being addressed by name in a group.
        const agents = (api.config as {
          agents?: { list?: Array<{ name?: string; default?: boolean }> };
        }).agents;
        const agentList = agents?.list ?? [];
        const configuredAgentName =
          agentList.find((entry) => entry.default)?.name ?? agentList[0]?.name ?? null;
        const mentionPatterns = [...resolved.mentionPatterns, configuredAgentName].filter(
          (pattern): pattern is string => typeof pattern === "string" && pattern.trim().length > 0,
        );

        // Inbound -> agent turn dispatch (Telegram-modeled): the bridge feeds each
        // received Marmot message into runChannelInboundEvent, and the agent's
        // reply is delivered back through send_final / live QUIC previews.
        const dispatch = createMarmotInboundDispatcher({
          cfg: api.config,
          runtimeChannel: api.runtime.channel as unknown as OpenClawChannelRuntime,
          client: clientForAccount(resolved),
          channelAccountId: resolved.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
          streamMode: resolved.streamMode,
          blockStreaming: resolved.blockStreaming,
          quicCandidates: resolved.quicCandidates,
          groupActivation: resolved.groupActivation,
          mentionPatterns,
          log: (message) => api.logger.info(message),
        });

        // Ambient surfacer: route a passive group event to the agent's session as
        // quiet next-turn context. Built here (over the full `api`) because it
        // needs `api.runtime.channel.routing` + `api.runtime.system`, which the
        // narrowed inbound api does not expose. Feature-detected at runtime so it
        // degrades to a no-op on a host without the system-event surface.
        const channelAccountId = resolved.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
        const surfaceAmbientEvent: MarmotAmbientSurfacer = ({ groupIdHex, text, contextKey }) => {
          const enqueue = api.runtime?.system?.enqueueSystemEvent;
          if (typeof enqueue !== "function") {
            api.logger.warn(
              "marmot: runtime has no system-event surface; ambient event not delivered",
            );
            return;
          }
          const route = api.runtime.channel.routing.resolveAgentRoute({
            cfg: api.config,
            channel: MARMOT_CHANNEL_ID,
            accountId: channelAccountId,
            peer: { kind: "group", id: groupIdHex },
          });
          enqueue(text, { sessionKey: route.sessionKey, contextKey: contextKey ?? null });
        };

        startMarmotInbound(api, dispatch, {
          configuredAgentName,
          surfaceAmbientEvent,
          invalidateGroupActivation: dispatch.invalidateGroupActivation,
          clearGroupActivationCache: dispatch.clearGroupActivationCache,
        });
      } catch {
        // This runs in a fire-and-forget IIFE, so an unguarded throw (e.g. a
        // malformed channels.marmot config that fails account resolution) would
        // surface as an unhandledRejection — and OpenClaw's handler process.exit(1)s
        // the whole gateway on a non-transient rejection, taking sibling channels
        // down with it. Contain it: log a privacy-safe notice and leave the Marmot
        // channel inert instead of crashing the gateway.
        api.logger.warn("marmot: inbound startup failed; channel is inactive");
      }
    })();
  },
});
