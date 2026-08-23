// Canary for the `openclaw/plugin-sdk/*` subpath exports this plugin links
// against at runtime.
//
// A named import that the installed SDK no longer exports is an ESM link error,
// so the whole plugin fails to initialize and OpenClaw loses the Marmot channel
// entirely — not just the feature that used the symbol. That is exactly what
// happened when 2026.7.2-beta re-cut `plugin-sdk/media-runtime` and dropped
// `assertLocalMediaAllowed` / `getDefaultLocalRoots` from it.
//
// Failing here on an SDK pin bump is much cheaper than failing at gateway
// startup on a user's machine. Each entry below must name a subpath and the
// runtime *values* (not types — those are erased) that our `src/` imports from
// it; type-only regressions are caught by `pnpm typecheck`.

import { describe, expect, it } from "vitest";

const RUNTIME_IMPORTS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["openclaw/plugin-sdk/channel-config-schema", ["buildJsonChannelConfigSchema"]],
  ["openclaw/plugin-sdk/channel-core", ["defineChannelPluginEntry", "defineSetupPluginEntry"]],
  ["openclaw/plugin-sdk/channel-inbound", ["buildChannelInboundEventContext", "runChannelInboundEvent"]],
  ["openclaw/plugin-sdk/channel-inbound-debounce", ["createInboundDebouncer"]],
  ["openclaw/plugin-sdk/channel-lifecycle", ["createAccountStatusSink", "runPassiveAccountLifecycle"]],
  [
    "openclaw/plugin-sdk/channel-outbound",
    ["defineChannelMessageAdapter", "deliverInboundReplyWithMessageSendContext"],
  ],
  ["openclaw/plugin-sdk/core", ["createChatChannelPlugin", "jsonResult", "KeyedAsyncQueue"]],
  ["openclaw/plugin-sdk/infra-runtime", ["readLocalFileFromRoots"]],
  ["openclaw/plugin-sdk/media-runtime", ["extractOriginalFilename", "getMediaDir"]],
  ["openclaw/plugin-sdk/media-store", ["saveMediaBuffer"]],
  [
    "openclaw/plugin-sdk/status-helpers",
    ["buildBaseChannelStatusSummary", "collectStatusIssuesFromLastError"],
  ],
  ["openclaw/plugin-sdk/web-media", ["LocalMediaAccessError", "getDefaultLocalRoots"]],
];

describe("OpenClaw plugin-sdk runtime surface", () => {
  for (const [subpath, symbols] of RUNTIME_IMPORTS) {
    it(
      `${subpath} exports the symbols the plugin imports`,
      async () => {
        const mod = (await import(subpath)) as Record<string, unknown>;
        const missing = symbols.filter((symbol) => mod[symbol] === undefined);
        expect(missing).toEqual([]);
      },
      20_000,
    );
  }
});
