// OpenClaw plugin runtime entry. Registers the Marmot channel and owns inbound
// subscriptions via `gateway.startAccount`. See README.md for setup.

import {
  defineChannelPluginEntry,
  type OpenClawPluginApi,
} from "openclaw/plugin-sdk/channel-core";

import { createMarmotChannelPlugin, MARMOT_CHANNEL_ID } from "./src/channel.js";

export default defineChannelPluginEntry({
  id: MARMOT_CHANNEL_ID,
  name: "Marmot",
  description: "End-to-end encrypted Marmot groups through the local wn-agent connector.",
  plugin: createMarmotChannelPlugin(),
  registerFull(api: OpenClawPluginApi) {
    api.logger.info(
      `marmot: registerFull invoked (registrationMode=${String(
        (api as { registrationMode?: unknown }).registrationMode ?? "unknown",
      )})`,
    );
  },
});
