// OpenClaw plugin runtime entry. Account lifecycle, including the inbound
// subscription, is owned by the channel's `gateway.startAccount` adapter.

import { defineChannelPluginEntry } from "openclaw/plugin-sdk/channel-core";

import { createMarmotChannelPlugin, MARMOT_CHANNEL_ID } from "./src/channel.js";
import { registerMarmotHistoryTool } from "./src/history-tool.js";

export default defineChannelPluginEntry({
  id: MARMOT_CHANNEL_ID,
  name: "Marmot",
  description: "End-to-end encrypted Marmot groups through the local wn-agent connector.",
  plugin: createMarmotChannelPlugin(),
  registerFull: registerMarmotHistoryTool,
});
