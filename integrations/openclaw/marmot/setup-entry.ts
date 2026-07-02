// Lightweight setup-only entry: exposes the channel for onboarding without
// starting the inbound subscription.

import { defineSetupPluginEntry } from "openclaw/plugin-sdk/channel-core";

import { createMarmotChannelPlugin } from "./src/channel.js";

export default defineSetupPluginEntry(createMarmotChannelPlugin());
