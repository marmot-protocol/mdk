// Marmot channel target-resolution (messaging) adapter for OpenClaw's shared
// `message` tool.
//
// A Marmot "conversation" is always an MLS group — a DM is just a two-member
// group — addressed by its group id hex. Without this adapter the generic
// `message` tool's target resolver has no way to recognize a Marmot group id:
// Marmot is not directory-backed, a bare group id matches none of core's
// id-like heuristics, and the channel exposed no `messaging.targetResolver`. So
// `message(action:"send", to:"<groupIdHex>")` fell straight through core's
// resolver to an "unknown target" error before the durable send could run —
// even though the auto-delivered final-reply path (see src/dispatch.ts) worked.
// When an agent routed its whole reply through that failing tool call, the reply
// was lost.
//
// Exposing `targetResolver.looksLikeId` + `inferTargetChatType` (plus a
// normalizing `resolveTarget` and the `marmot:` prefix) makes a Marmot group id
// a first-class, resolvable target, so an agent-driven send routes to the right
// conversation. This only affects target resolution for the `message` tool; the
// inbound auto-reply path sends through wn-agent directly and is unchanged.

import type {
  ChannelMessagingAdapter,
  ChatType,
} from "openclaw/plugin-sdk/channel-runtime";

import {
  isMarmotGroupIdHex,
  MARMOT_TARGET_PREFIX,
  tryCanonicalizeMarmotGroupTarget,
} from "./target.js";

export { isMarmotGroupIdHex, MARMOT_TARGET_PREFIX } from "./target.js";

/**
 * Normalize a raw target into a bare Marmot group id hex, or `undefined` when it
 * is not a Marmot group id. Accepts bare hex, `marmot:<hex>`, and internal
 * `group:<hex>` announce/fallback routes.
 */
export function normalizeMarmotTarget(raw: string): string | undefined {
  return tryCanonicalizeMarmotGroupTarget(raw);
}

/**
 * Whether a raw `message`-tool target looks like a Marmot conversation id. An
 * explicit `marmot:` prefix always qualifies (the agent named our channel); a
 * bare value qualifies when it normalizes to a valid group id hex. Used as
 * `targetResolver.looksLikeId` so core short-circuits its directory search
 * (Marmot has none) and treats a group id as an explicit id.
 */
export function looksLikeMarmotTarget(raw: string): boolean {
  if (raw.trim().toLowerCase().startsWith(`${MARMOT_TARGET_PREFIX}:`)) {
    return true;
  }
  return normalizeMarmotTarget(raw) !== undefined;
}

/**
 * Build the Marmot messaging adapter for OpenClaw's shared `message` tool.
 *
 * - `inferTargetChatType` always returns `"group"`: every Marmot conversation is
 *   an MLS group, so core builds the outbound session route as a group route —
 *   matching the inbound `resolveAgentRoute({peer:{kind:"group"}})` in
 *   src/dispatch.ts — and an agent-driven send lands in the same session.
 * - `targetResolver.looksLikeId` lets a bare or `marmot:`-prefixed group id skip
 *   directory search and resolve as an explicit id.
 * - `targetResolver.resolveTarget` normalizes the input to the bare hex wn-agent
 *   expects and tags it as a group; it returns `null` for anything that is not a
 *   Marmot group id so an invalid target still fails cleanly (with `hint`).
 * - `targetPrefixes` lets `marmot:<hex>` self-route to this channel and lets core
 *   reject another channel's prefix.
 * - `normalizeTarget` strips the `marmot:`/`0x` decoration so the resolved `to`
 *   is the bare group id hex.
 */
export function createMarmotMessagingAdapter(): ChannelMessagingAdapter {
  return {
    targetPrefixes: [MARMOT_TARGET_PREFIX],
    normalizeTarget: (raw) => normalizeMarmotTarget(raw),
    inferTargetChatType: (): ChatType => "group",
    targetResolver: {
      hint: "<marmot group id hex, e.g. marmot:<hex> or the bare hex>",
      looksLikeId: (raw) => looksLikeMarmotTarget(raw),
      resolveTarget: async ({ input, normalized }) => {
        const to = normalizeMarmotTarget(input) ?? normalizeMarmotTarget(normalized);
        if (!to) {
          return null;
        }
        return { to, kind: "group", source: "normalized" };
      },
    },
  };
}
