// Inbound -> agent turn dispatch. The channel builds one authoritative OpenClaw
// route from the received Marmot group, runs the agent turn, and sends its final
// through OpenClaw's durable message context. That context invokes the channel's
// registered Marmot message adapter, which is the only durable wn-agent send path.
//
// The turn assembly (runChannelInboundEvent / buildChannelInboundEventContext /
// api.runtime.channel) is typechecked against the SDK and validated by the
// connector E2E. Inbound production turns are deliberately final-only for now.

import { readFile, unlink } from "node:fs/promises";

import {
  buildChannelInboundEventContext,
  runChannelInboundEvent,
  type InboundMediaFacts,
} from "openclaw/plugin-sdk/channel-inbound";
import {
  deliverInboundReplyWithMessageSendContext,
  type DurableInboundReplyDeliveryResult,
} from "openclaw/plugin-sdk/channel-outbound";
import { saveMediaBuffer } from "openclaw/plugin-sdk/media-store";
import type { ReplyPayload } from "openclaw/plugin-sdk/reply-payload";

import type { MarmotAgentControlClient } from "./client.js";
import type { GroupActivation } from "./config.js";
import type { MarmotInboundMessage } from "./inbound.js";
import { DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID } from "./runtime-state.js";

// --- inbound turn dispatch (SDK-coupled; harness-validated) ------------------

/** Kind of reply delivery emitted by OpenClaw's buffered dispatcher. */
export interface ReplyDelivery {
  kind: "final" | "block" | "tool";
}

/** Reply payload emitted by OpenClaw's buffered reply dispatcher. */
export type ReplyPayloadLike = ReplyPayload;

const MARMOT_TURN_DENIED_TOOLS = ["sessions_send"] as const;

/**
 * Keep cross-session coordination out of a source-bound Marmot reply turn.
 * `sessions_send` does not deliver to a human-facing channel; normal final text
 * and the shared `message` tool already use the authoritative source route.
 */
export function buildMarmotTurnConfig(baseCfg: unknown): Record<string, unknown> {
  const cfg = baseCfg as { tools?: { deny?: string[] } };
  return {
    ...cfg,
    tools: {
      ...cfg.tools,
      deny: [...new Set([...(cfg.tools?.deny ?? []), ...MARMOT_TURN_DENIED_TOOLS])],
    },
  };
}

/** Narrow view of `api.runtime.channel` (only the members we drive). */
export interface OpenClawChannelRuntime {
  routing: {
    resolveAgentRoute: (input: unknown) => {
      agentId: string;
      accountId: string;
      sessionKey: string;
    };
  };
  session: {
    resolveStorePath: (store?: string, opts?: unknown) => string;
    recordInboundSession: unknown;
  };
  reply: {
    dispatchReplyWithBufferedBlockDispatcher: (params: unknown) => Promise<unknown>;
  };
}

/**
 * Dispatcher client: the group-info read used for activation gating and the
 * media download used to surface inbound images to the agent.
 */
export type MarmotDispatchClient = Pick<MarmotAgentControlClient, "groupInfo" | "downloadMedia">;

export interface MarmotDispatchDeps {
  /** Full OpenClaw config (`api.config`). */
  cfg: unknown;
  /** `api.runtime.channel`. */
  runtimeChannel: OpenClawChannelRuntime;
  client: MarmotDispatchClient;
  /** OpenClaw channel account id ("default" or a configured account key), not the Marmot account hex. */
  channelAccountId?: string | null;
  /** When to reply in a multi-party group ("mention" gates; "always" replies to all). */
  groupActivation: GroupActivation;
  /** Case-insensitive trigger phrases that count as addressing the agent. */
  mentionPatterns: string[];
  /** Optional privacy-safe lifecycle logger. */
  log?: (message: string) => void;
  /** Override OpenClaw durable delivery in focused tests. */
  deliverInboundReply?: typeof deliverInboundReplyWithMessageSendContext;
}

function assertDurableReplyHandled(result: DurableInboundReplyDeliveryResult): void {
  if (result.status === "handled_visible" || result.status === "handled_no_send") {
    return;
  }
  if (result.status === "failed") {
    throw result.error;
  }
  throw new Error(`marmot: OpenClaw durable reply was not handled (${result.reason})`);
}

/** Whether the message text contains any configured trigger phrase. */
function matchesMentionPattern(text: string, patterns: string[]): boolean {
  if (patterns.length === 0) {
    return false;
  }
  const haystack = text.toLowerCase();
  return patterns.some((pattern) => {
    const needle = pattern.trim().toLowerCase();
    return needle.length > 0 && haystack.includes(needle);
  });
}

/**
 * Per-(account, group) cache of the `is_direct` activation fact. `is_direct`
 * (the group has exactly two members → effective DM → always reply) only changes
 * when membership changes, so it is cached after the first lookup and reused for
 * every subsequent unaddressed message in that group. The inbound runtime
 * invalidates an entry when wn-agent reports a `group_state_changed` event for
 * the group (membership/admin/rename/avatar), so the next unaddressed message
 * re-reads fresh membership. Keyed on `${accountIdHex}:${groupIdHex}`; both are
 * already lowercase hex (the client normalizes them), and neither the key nor
 * the cached boolean is ever logged.
 */
export class GroupActivationCache {
  private readonly isDirect = new Map<string, boolean>();

  private static key(accountIdHex: string, groupIdHex: string): string {
    return `${accountIdHex}:${groupIdHex}`;
  }

  get(accountIdHex: string, groupIdHex: string): boolean | undefined {
    return this.isDirect.get(GroupActivationCache.key(accountIdHex, groupIdHex));
  }

  set(accountIdHex: string, groupIdHex: string, isDirect: boolean): void {
    this.isDirect.set(GroupActivationCache.key(accountIdHex, groupIdHex), isDirect);
  }

  /** Drop the cached activation fact for one group; the next gate re-reads membership. */
  invalidate(accountIdHex: string, groupIdHex: string): void {
    this.isDirect.delete(GroupActivationCache.key(accountIdHex, groupIdHex));
  }

  /** Drop every cached activation fact (e.g. on an inbound resync). */
  clear(): void {
    this.isDirect.clear();
  }
}

/**
 * Decide whether an inbound group message should run an agent turn. Always reply
 * when addressed (`mentionsSelf`, a trigger matches) or in an effective DM
 * (exactly two members). Membership is queried lazily — only when the message is
 * otherwise unaddressed — to avoid a round-trip on the common addressed case, and
 * the `is_direct` result is cached per (account, group) so repeated ambient
 * messages don't each re-read MLS state (the cache is invalidated on a
 * `group_state_changed` event). On a membership-lookup error we fail **closed**
 * (skip the turn): under the `mention` policy an unaddressed message in a group
 * whose membership we can't resolve is more likely a multi-party conversation the
 * agent wasn't addressed in, and barging in there is worse (and unrecallable)
 * than dropping a single reply in a true two-party DM, where the user can simply
 * re-send or address the agent explicitly. The error is not cached.
 */
async function shouldRunTurn(
  deps: MarmotDispatchDeps,
  cache: GroupActivationCache,
  message: MarmotInboundMessage,
): Promise<boolean> {
  if (deps.groupActivation === "always") {
    return true;
  }
  if (message.mentionsSelf) {
    return true;
  }
  if (matchesMentionPattern(message.text, deps.mentionPatterns)) {
    return true;
  }
  const cached = cache.get(message.accountIdHex, message.groupIdHex);
  if (cached !== undefined) {
    return cached;
  }
  try {
    const info = await deps.client.groupInfo(message.accountIdHex, message.groupIdHex);
    cache.set(message.accountIdHex, message.groupIdHex, info.is_direct);
    return info.is_direct;
  } catch {
    deps.log?.("marmot: group membership lookup failed; skipping turn (fail-closed)");
    return false;
  }
}

/** Map a media MIME type onto the OpenClaw inbound media `kind` enum. */
function inboundMediaKind(mediaType: string): NonNullable<InboundMediaFacts["kind"]> {
  const type = mediaType.trim().toLowerCase();
  if (type.startsWith("image/")) {
    return "image";
  }
  if (type.startsWith("video/")) {
    return "video";
  }
  if (type.startsWith("audio/")) {
    return "audio";
  }
  if (type.length === 0) {
    return "unknown";
  }
  return "document";
}

/**
 * Best-effort: download each inbound media ref to a local path on the wn-agent
 * host, then re-stage the decrypted bytes through OpenClaw's official media store
 * so the resulting path is under an allowlisted media root. Native vision trusts
 * the path directly, but the agent's `image` tool enforces an allowlist
 * (`assertLocalMediaAllowed`) whose roots are OpenClaw's media dir — the raw
 * wn-agent temp path is not under them, so the tool would reject it. Building the
 * `InboundMediaFacts` from the staged path keeps both paths working. The wn-agent
 * temp file is unlinked (best-effort) once re-staged. A ref that fails is skipped
 * (privacy-safe log) so one broken attachment never drops the whole turn. Returns
 * `undefined` when the message carries no media so the context builder omits the
 * field entirely.
 */
async function downloadInboundMedia(
  deps: Pick<MarmotDispatchClient, "downloadMedia">,
  message: MarmotInboundMessage,
  log?: (message: string) => void,
): Promise<InboundMediaFacts[] | undefined> {
  const refs = message.media ?? [];
  if (refs.length === 0) {
    return undefined;
  }
  const facts: InboundMediaFacts[] = [];
  for (const ref of refs) {
    // Captured so the wn-agent temp file is unlinked even if readFile or
    // saveMediaBuffer throws after a successful download.
    let tempPath: string | undefined;
    try {
      const res = await deps.downloadMedia(message.accountIdHex, message.groupIdHex, ref);
      tempPath = res.path;
      const buffer = await readFile(res.path);
      const saved = await saveMediaBuffer(buffer, res.media_type, "inbound", undefined, res.file_name);
      facts.push({
        path: saved.path,
        contentType: res.media_type,
        kind: inboundMediaKind(res.media_type),
        messageId: message.messageIdHex,
      });
    } catch {
      log?.("marmot: inbound media download failed; skipping attachment");
    } finally {
      // The wn-agent temp file is redundant once re-staged (or unusable on a
      // mid-stage failure); drop it (best-effort).
      if (tempPath !== undefined) {
        await unlink(tempPath).catch(() => undefined);
      }
    }
  }
  return facts.length > 0 ? facts : undefined;
}

/**
 * The inbound dispatcher callable plus a cache-invalidation hook. The function
 * runs an agent turn for a received message; `invalidateGroupActivation` drops
 * the cached `is_direct` activation fact for a group whose membership changed
 * (driven by the inbound runtime's `group_state_changed` handler), and
 * `clearGroupActivationCache` drops every entry (e.g. on an inbound resync).
 */
export type MarmotInboundDispatcher = ((message: MarmotInboundMessage) => Promise<void>) & {
  invalidateGroupActivation: (accountIdHex: string, groupIdHex: string) => void;
  clearGroupActivationCache: () => void;
};

/**
 * Build the inbound dispatcher: for each received Marmot message, resolve the
 * agent route, build the inbound context, and run it through the OpenClaw turn
 * kernel. Final replies re-enter OpenClaw's durable message context, which uses
 * the registered Marmot message adapter and its trusted source route.
 */
export function createMarmotInboundDispatcher(
  deps: MarmotDispatchDeps,
): MarmotInboundDispatcher {
  // Per-(account, group) is_direct cache, scoped to this dispatcher instance so
  // it lives exactly as long as the inbound subscription that owns it.
  const activationCache = new GroupActivationCache();
  const dispatch = async (message: MarmotInboundMessage): Promise<void> => {
    // Activation gating: in a multi-party group, only run a turn when addressed.
    if (!(await shouldRunTurn(deps, activationCache, message))) {
      deps.log?.("marmot: inbound not addressed; skipping turn (groupActivation=mention)");
      return;
    }
    const channelAccountId = deps.channelAccountId?.trim() || DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
    const route = deps.runtimeChannel.routing.resolveAgentRoute({
      cfg: deps.cfg,
      channel: "marmot",
      accountId: channelAccountId,
      peer: { kind: "group", id: message.groupIdHex },
    });

    // Surface any inbound encrypted media to the agent: download each ref to a
    // local path (wn-agent decrypts; the content key never leaves it) and hand
    // the local file facts to OpenClaw, which reads + base64-encodes them.
    const media = await downloadInboundMedia(deps.client, message, deps.log);

    const ctxPayload = buildChannelInboundEventContext({
      channel: "marmot",
      accountId: channelAccountId,
      messageId: message.messageIdHex,
      from: message.senderAccountIdHex,
      sender: {
        id: message.senderAccountIdHex,
        ...(message.senderDisplayName ? { name: message.senderDisplayName } : {}),
      },
      conversation: { kind: "group", id: message.groupIdHex },
      route: {
        agentId: route.agentId,
        accountId: route.accountId,
        routeSessionKey: route.sessionKey,
      },
      reply: {
        to: message.groupIdHex,
        ...(message.replyToMessageIdHex ? { replyToId: message.replyToMessageIdHex } : {}),
      },
      message: { rawBody: message.text, bodyForAgent: message.text },
      ...(media ? { media } : {}),
    });

    const storePath = deps.runtimeChannel.session.resolveStorePath();
    const turnCfg = buildMarmotTurnConfig(deps.cfg);
    const deliverInboundReply =
      deps.deliverInboundReply ?? deliverInboundReplyWithMessageSendContext;
    let finalDeliveries = 0;
    deps.log?.("marmot: agent turn starting");
    await runChannelInboundEvent({
      channel: "marmot",
      accountId: channelAccountId,
      raw: message,
      adapter: {
        ingest: () => ({
          id: message.messageIdHex,
          rawText: message.text,
          textForAgent: message.text,
        }),
        resolveTurn: () => ({
          channel: "marmot",
          accountId: channelAccountId,
          routeSessionKey: route.sessionKey,
          storePath,
          ctxPayload,
          recordInboundSession: deps.runtimeChannel.session.recordInboundSession as never,
          runDispatch: () =>
            deps.runtimeChannel.reply.dispatchReplyWithBufferedBlockDispatcher({
              ctx: ctxPayload,
              cfg: turnCfg,
              dispatcherOptions: {
                deliver: async (payload: ReplyPayloadLike, info: ReplyDelivery) => {
                  if (info.kind !== "final") {
                    return;
                  }
                  finalDeliveries += 1;
                  const result = await deliverInboundReply({
                    cfg: turnCfg as never,
                    channel: "marmot",
                    accountId: route.accountId,
                    agentId: route.agentId,
                    ctxPayload,
                    payload,
                    info,
                    // A normal response threads to the inbound message that
                    // triggered this turn. The destination itself comes from
                    // ctxPayload.OriginatingTo / ctxPayload.To.
                    replyToId: message.messageIdHex,
                  });
                  assertDurableReplyHandled(result);
                },
              },
              replyOptions: {
                sourceReplyDeliveryMode: "automatic",
                // Keep the initial contract final-only. QUIC previews can be
                // reintroduced later through the standard message-adapter live
                // lifecycle without creating a second durable send path.
                disableBlockStreaming: true,
              },
            }) as never,
        }),
      },
    });
    deps.log?.(`marmot: agent turn done (final deliveries=${finalDeliveries})`);
  };

  return Object.assign(dispatch, {
    invalidateGroupActivation: (accountIdHex: string, groupIdHex: string) =>
      activationCache.invalidate(accountIdHex, groupIdHex),
    clearGroupActivationCache: () => activationCache.clear(),
  });
}
