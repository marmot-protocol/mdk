import type { createMarmotChannelPlugin } from "../src/channel.js";

// The host loader is deliberately test-only and has no SDK export or public
// declarations. Exercise its real runtime facade, with the narrow shape these
// integration tests consume, whenever the pinned SDK changes.
const loader = await import(
  new URL("../node_modules/openclaw/dist/plugins/loader.js", import.meta.url).href
);

export const loadOpenClawPlugins = loader.loadOpenClawPlugins as (
  options: Record<string, unknown>,
) => {
  channels: Array<{ plugin: ReturnType<typeof createMarmotChannelPlugin> }>;
  diagnostics: unknown[];
};
export const clearPluginRegistryLoadCache = loader.clearPluginRegistryLoadCache as () => void;
