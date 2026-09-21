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
import { deliverInboundReplyWithMessageSendContext } from "openclaw/plugin-sdk/channel-outbound";
import { saveMediaBuffer } from "openclaw/plugin-sdk/media-store";
import type { ReplyPayload } from "openclaw/plugin-sdk/reply-payload";

import type {
  AgentControlTimelineMessage,
  MarmotAgentControlClient,
} from "./client.js";
import type { GroupActivation } from "./config.js";
import { GroupInfoCache, type GroupInfoFacts } from "./group-info-cache.js";
import type { MarmotInboundMessage } from "./inbound.js";
import { DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID } from "./runtime-state.js";
import {
  authorizeInboundSender,
  senderAuthorizationInputFromMessage,
  type MarmotSenderAuthorizer,
} from "./sender-policy.js";

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
export type MarmotDispatchClient = Pick<
  MarmotAgentControlClient,
  "groupInfo" | "downloadMedia" | "timelineList"
>;

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
  /**
   * Account-bound sender ACL. Missing authorizer is fail-closed so a direct
   * caller or wiring error cannot skip intake authorization.
   */
  authorizer?: MarmotSenderAuthorizer | null;
  /** Optional privacy-safe lifecycle logger. */
  log?: (message: string) => void;
  /** Override OpenClaw durable delivery in focused tests. */
  deliverInboundReply?: typeof deliverInboundReplyWithMessageSendContext;
}

/**
 * Derived from the delivery function rather than imported by name: the
 * `DurableInboundReplyDeliveryResult` alias is not re-exported from
 * `plugin-sdk/channel-outbound` on the beta channel, but the function's return
 * type is identical on both.
 */
type DurableInboundReplyDeliveryResult = Awaited<
  ReturnType<typeof deliverInboundReplyWithMessageSendContext>
>;

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

function marmotGroupResolution(groupIdHex: string): {
  key: string;
  channel: "marmot";
  id: string;
  chatType: "group";
} {
  return {
    key: `marmot:group:${groupIdHex}`,
    channel: "marmot",
    id: groupIdHex,
    chatType: "group",
  };
}

type ActivationDecision = { run: false } | { run: true; facts?: GroupInfoFacts };

/**
 * Decide whether an inbound group message should run an agent turn. Always reply
 * when addressed (`mentionsSelf`, a trigger matches) or in an effective DM
 * (exactly two members). Membership is queried only when the message is
 * otherwise unaddressed. Addressed and always-on turns still share the same
 * bounded group-info cache so a later ambient message can reuse `is_direct`
 * and the normalized subject without a second control-socket read. On a
 * membership-lookup error we fail **closed** (skip the turn): under the
 * `mention` policy an unaddressed message in a group whose membership we can't
 * resolve is more likely a multi-party conversation the agent wasn't addressed
 * in, and barging in there is worse (and unrecallable) than dropping a single
 * reply in a true two-party DM, where the user can simply re-send or address
 * the agent explicitly. Membership errors are not cached as `isDirect: false`.
 */
async function decideActivation(
  deps: MarmotDispatchDeps,
  cache: GroupInfoCache,
  message: MarmotInboundMessage,
): Promise<ActivationDecision> {
  if (
    deps.groupActivation === "always" ||
    message.mentionsSelf ||
    matchesMentionPattern(message.text, deps.mentionPatterns)
  ) {
    return { run: true };
  }
  const result = await cache.lookup(
    message.accountIdHex,
    message.groupIdHex,
    "activation",
    () => deps.client.groupInfo(message.accountIdHex, message.groupIdHex),
  );
  if (result.status === "ok") {
    return result.facts.isDirect ? { run: true, facts: result.facts } : { run: false };
  }
  deps.log?.("marmot: group membership lookup failed; skipping turn (fail-closed)");
  return { run: false };
}

async function resolveGroupFacts(
  deps: MarmotDispatchDeps,
  cache: GroupInfoCache,
  message: MarmotInboundMessage,
  existing?: GroupInfoFacts,
): Promise<GroupInfoFacts | undefined> {
  if (existing) {
    return existing;
  }
  const result = await cache.lookup(
    message.accountIdHex,
    message.groupIdHex,
    "label",
    () => deps.client.groupInfo(message.accountIdHex, message.groupIdHex),
  );
  if (result.status === "ok") {
    return result.facts;
  }
  if (result.status === "failed") {
    deps.log?.("marmot: group info lookup failed; continuing without label");
  }
  return undefined;
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

function replyFallbackBody(availability: string): string {
  switch (availability) {
    case "deleted":
      return "[Referenced message was deleted]";
    case "invalidated":
      return "[Referenced message was invalidated]";
    case "missing":
      return "[Referenced message is unavailable]";
    default:
      return "";
  }
}

/**
 * Aggregate bound for the rendered conversation-history supplemental entry,
 * mirroring the Hermes adapter-local bound (#1223): retain at most the newest
 * eight records and keep the complete serialized entry — envelope, records,
 * and aggregate truncation metadata — within 16 KiB of UTF-8.
 */
export const TIMELINE_CONTEXT_MESSAGE_LIMIT = 8;
export const TIMELINE_CONTEXT_BYTE_LIMIT = 16 * 1024;

interface TimelineContextPayload {
  order: "chronological";
  relation: "before_current_message";
  messages: AgentControlTimelineMessage[];
  messages_truncated?: boolean;
  omitted_message_count?: number;
  oversized_message_count?: number;
}

function timelineContextEntry(payload: TimelineContextPayload) {
  return {
    label: "Marmot conversation history",
    source: "marmot",
    type: "chat_window",
    payload,
  };
}

/** UTF-8 size of the complete serialized supplemental entry. */
function timelineContextEntryBytes(payload: TimelineContextPayload): number {
  return Buffer.byteLength(JSON.stringify(timelineContextEntry(payload)), "utf8");
}

/**
 * Whether one record alone already exceeds the budget, judged against an entry
 * carrying the truncation metadata that would accompany its omission.
 */
function timelineMessageExceedsByteLimit(message: AgentControlTimelineMessage): boolean {
  return (
    timelineContextEntryBytes({
      order: "chronological",
      relation: "before_current_message",
      messages: [message],
      messages_truncated: true,
      omitted_message_count: 1,
    }) > TIMELINE_CONTEXT_BYTE_LIMIT
  );
}

/**
 * Build the bounded conversation-history entry: drop oldest records first,
 * keep retained records in chronological order, and omit an oversized
 * remaining record rather than exceed the byte budget. Reports only aggregate
 * omitted/oversized counts (privacy-safe). `oversized_message_count` counts
 * every omitted record that is individually unrenderable — including records
 * dropped by the count window, where size never drove the decision — matching
 * the Hermes adapter's shared contract.
 */
function boundTimelineContextEntry(history: AgentControlTimelineMessage[]) {
  const bounded = history.slice(-TIMELINE_CONTEXT_MESSAGE_LIMIT);
  let omittedMessageCount = history.length - bounded.length;
  let oversizedMessageCount = 0;
  for (const message of history.slice(0, omittedMessageCount)) {
    if (timelineMessageExceedsByteLimit(message)) {
      oversizedMessageCount += 1;
    }
  }

  for (;;) {
    const payload: TimelineContextPayload = {
      order: "chronological",
      relation: "before_current_message",
      messages: bounded,
      ...(omittedMessageCount > 0
        ? { messages_truncated: true, omitted_message_count: omittedMessageCount }
        : {}),
      ...(oversizedMessageCount > 0 ? { oversized_message_count: oversizedMessageCount } : {}),
    };
    if (timelineContextEntryBytes(payload) <= TIMELINE_CONTEXT_BYTE_LIMIT) {
      return timelineContextEntry(payload);
    }
    // Always defined: an empty `bounded` renders a metadata-only payload that
    // fits the budget, so the check above returns before `shift` can drain it.
    const dropped = bounded.shift() as AgentControlTimelineMessage;
    if (timelineMessageExceedsByteLimit(dropped)) {
      oversizedMessageCount += 1;
    }
    omittedMessageCount += 1;
  }
}

/**
 * Convert Marmot reply hydration and buffered ambient facts into OpenClaw's
 * native, explicitly-untrusted supplemental context. None of this data enters a
 * system prompt, and ambient events never invoke this dispatcher themselves.
 */
function inboundSupplemental(
  message: MarmotInboundMessage,
  history: AgentControlTimelineMessage[] = [],
) {
  const reply = message.replyTo;
  const untrustedContext: Array<{
    label: string;
    source: string;
    type: string;
    payload: unknown;
  }> = [];
  if (reply) {
    untrustedContext.push({
      label: "Marmot referenced-message context",
      source: "marmot",
      type: "referenced_message",
      payload: {
        message_id_hex: reply.message_id_hex,
        availability: reply.availability,
        sender: reply.sender,
        recorded_at: reply.recorded_at,
        text_excerpt: reply.text_excerpt,
        attachments: reply.attachments ?? [],
        attachments_truncated: reply.attachments_truncated,
        text_truncated: reply.text_truncated,
      },
    });
  }
  if (history.length > 0) {
    untrustedContext.push(boundTimelineContextEntry(history));
  }
  for (const ambient of message.ambientContext ?? []) {
    untrustedContext.push({
      label: "Marmot ambient conversation event",
      source: "marmot",
      type: ambient.type,
      payload: ambient,
    });
  }
  if (!reply && untrustedContext.length === 0) {
    return undefined;
  }
  return {
    ...(reply
      ? {
          quote: {
            id: reply.message_id_hex,
            body: reply.text_excerpt ?? replyFallbackBody(reply.availability),
            sender:
              reply.sender?.display_name ??
              reply.sender?.account_id_hex ??
              "Unknown Marmot participant",
            isQuote: true,
            isSelf: reply.sender?.is_self ?? false,
          },
        }
      : {}),
    ...(untrustedContext.length > 0 ? { untrustedContext } : {}),
  };
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
 * the cached group-info facts for a group whose membership or subject changed
 * (driven by the inbound runtime's `group_state_changed` handler), and
 * `clearGroupActivationCache` drops every entry (e.g. on an inbound resync or
 * subscription reconnect). Hook names stay stable for gateway compatibility.
 */
export type MarmotInboundDispatcher = ((message: MarmotInboundMessage) => Promise<boolean>) & {
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
  // Per-(account, group) facts cache, scoped to this dispatcher instance so it
  // lives exactly as long as the inbound subscription that owns it.
  const groupInfoCache = new GroupInfoCache();
  const dispatch = async (message: MarmotInboundMessage): Promise<boolean> => {
    const authorization = authorizeInboundSender(
      deps.authorizer,
      senderAuthorizationInputFromMessage(message),
    );
    if (authorization.outcome === "deny") {
      deps.log?.(`marmot: inbound sender denied (reason=${authorization.reason})`);
      return false;
    }
    // Activation gating: in a multi-party group, only run a turn when addressed.
    const decision = await decideActivation(deps, groupInfoCache, message);
    if (!decision.run) {
      deps.log?.("marmot: inbound not addressed; skipping turn (groupActivation=mention)");
      return false;
    }
    const groupFacts = await resolveGroupFacts(deps, groupInfoCache, message, decision.facts);
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
    let history: AgentControlTimelineMessage[] = [];
    try {
      const page = await deps.client.timelineList(
        message.accountIdHex,
        message.groupIdHex,
        {
          before: {
            recorded_at: message.recordedAt ?? 0,
            message_id_hex: message.messageIdHex,
          },
          // Deliberately over-fetch beyond TIMELINE_CONTEXT_MESSAGE_LIMIT so
          // the bounded entry can report an exact omitted_message_count.
          limit: 20,
        },
      );
      history = page.messages;
    } catch {
      deps.log?.("marmot: conversation history lookup failed; continuing without history");
    }
    const supplemental = inboundSupplemental(message, history);

    const ctxPayload = await buildChannelInboundEventContext({
      channel: "marmot",
      accountId: channelAccountId,
      messageId: message.messageIdHex,
      timestamp: (message.recordedAt ?? 0) * 1000,
      from: message.senderAccountIdHex,
      sender: {
        id: message.senderAccountIdHex,
        ...(message.senderDisplayName ? { name: message.senderDisplayName } : {}),
      },
      conversation: {
        kind: "group",
        id: message.groupIdHex,
        ...(groupFacts?.label ? { label: groupFacts.label } : {}),
      },
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
      ...(supplemental ? { supplemental } : {}),
      resolveSupplementalMedia: true,
      suppressSelfQuoteBody: false,
    });

    const sessionStore = (deps.cfg as { session?: { store?: string } }).session?.store;
    const storePath = deps.runtimeChannel.session.resolveStorePath(sessionStore, {
      agentId: route.agentId,
    });
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
          record: {
            groupResolution: marmotGroupResolution(message.groupIdHex),
          },
          // OpenClaw 2026.7.2-beta requires prepared dispatch runners to
          // declare who owns their adoption lifecycle. Marmot does not create
          // a durable adoption resource outside runDispatch, so a skipped turn
          // has nothing to release. Stable 2026.7.1 ignores this additive
          // property, letting one packaged adapter run on both SDK contracts.
          runDispatchLifecycle: {
            turnAdoptionLifecycle: undefined,
            onDispatchSkipped: async () => undefined,
          },
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
    return true;
  };

  return Object.assign(dispatch, {
    invalidateGroupActivation: (accountIdHex: string, groupIdHex: string) =>
      groupInfoCache.invalidate(accountIdHex, groupIdHex),
    clearGroupActivationCache: () => groupInfoCache.clear(),
  });
}
