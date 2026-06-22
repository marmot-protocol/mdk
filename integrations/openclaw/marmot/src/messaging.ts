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
// inbound auto-reply path sends through dm-agent directly and is unchanged.

import type {
  ChannelMessagingAdapter,
  ChatType,
} from "openclaw/plugin-sdk/channel-runtime";

/** Explicit cross-channel target prefix, e.g. `marmot:<groupIdHex>`. */
export const MARMOT_TARGET_PREFIX = "marmot";

// Marmot conversation ids are MLS group ids: opaque byte strings rendered as
// lowercase hex. OpenMLS mints a 16-byte (32 hex char) id at group creation; a
// wider even-length band is accepted so a non-default-length group id still
// resolves, while staying narrow enough not to swallow unrelated short tokens.
const MIN_GROUP_ID_HEX_CHARS = 32;
const MAX_GROUP_ID_HEX_CHARS = 128;

/** True for an even-length lowercase hex string in the Marmot group-id size band. */
export function isMarmotGroupIdHex(value: string): boolean {
  if (value.length < MIN_GROUP_ID_HEX_CHARS || value.length > MAX_GROUP_ID_HEX_CHARS) {
    return false;
  }
  if (value.length % 2 !== 0) {
    return false;
  }
  return /^[0-9a-f]+$/.test(value);
}

/**
 * Normalize a raw target into a bare Marmot group id hex, or `undefined` when it
 * is not a Marmot group id. Strips an optional `marmot:` channel prefix and an
 * optional `0x`, lowercases, and validates an even-length hex string within the
 * group-id size band. The returned value is exactly what dm-agent's `send_final`
 * expects as the group id (no prefix), matching `normalizeHex` in src/client.ts.
 */
export function normalizeMarmotTarget(raw: string): string | undefined {
  let text = raw.trim().toLowerCase();
  if (text.startsWith(`${MARMOT_TARGET_PREFIX}:`)) {
    text = text.slice(MARMOT_TARGET_PREFIX.length + 1).trim();
  }
  if (text.startsWith("0x")) {
    text = text.slice(2);
  }
  return isMarmotGroupIdHex(text) ? text : undefined;
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
 * - `targetResolver.resolveTarget` normalizes the input to the bare hex dm-agent
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
