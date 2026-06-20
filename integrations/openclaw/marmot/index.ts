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
import { startMarmotInbound, syncMarmotAllowlist } from "./src/inbound-runtime.js";
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
      // Mirror configured dm.allowFrom welcomers into dm-agent before consuming
      // inbound, so the welcomer policy is in place when the agent goes live.
      // (syncMarmotAllowlist is self-guarded and never rejects.)
      await syncMarmotAllowlist(api);

      // Inbound -> agent turn dispatch (Telegram-modeled): the bridge feeds each
      // received Marmot message into runChannelInboundEvent, and the agent's
      // reply is delivered back through send_final / live QUIC previews.
      const resolved = resolveMarmotChannelAccount(api.config, null);
      const dispatch = createMarmotInboundDispatcher({
        cfg: api.config,
        runtimeChannel: api.runtime.channel as unknown as OpenClawChannelRuntime,
        client: clientForAccount(resolved),
        channelAccountId: resolved.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
        streamMode: resolved.streamMode,
        blockStreaming: resolved.blockStreaming,
        quicCandidates: resolved.quicCandidates,
        log: (message) => api.logger.info(message),
      });

      // Inherit the configured OpenClaw agent name (if any) for the optional
      // Nostr profile-name onboarding flow; otherwise it asks in-chat.
      const agents = (api.config as {
        agents?: { list?: Array<{ name?: string; default?: boolean }> };
      }).agents;
      const agentList = agents?.list ?? [];
      const configuredAgentName =
        agentList.find((entry) => entry.default)?.name ?? agentList[0]?.name ?? null;

      startMarmotInbound(api, dispatch, { configuredAgentName });
    })();
  },
});
