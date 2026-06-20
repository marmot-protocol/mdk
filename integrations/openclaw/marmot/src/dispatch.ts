// Inbound -> agent turn dispatch, modeled on the bundled OpenClaw Telegram
// channel (node_modules/openclaw/dist/bot-*.js): the channel owns its inbound
// loop and calls `runChannelInboundEvent` itself, with a `resolveTurn` whose
// `runDispatch` drives `dispatchReplyWithBufferedBlockDispatcher`. The agent's
// reply arrives as progressive `block` deliveries + a `final` via a
// `deliver(payload, info)` callback, which we map onto Marmot sends.
//
// The turn assembly (runChannelInboundEvent / buildChannelInboundEventContext /
// api.runtime.channel) is typechecked against the SDK but is validated
// end-to-end against the `openclaw-gateway` docker harness (it needs a running
// gateway + a model). The MarmotReplySink mapping below is unit-tested.

import { randomUUID } from "node:crypto";
import { readFile, unlink } from "node:fs/promises";

import {
  buildChannelInboundEventContext,
  runChannelInboundEvent,
  type InboundMediaFacts,
} from "openclaw/plugin-sdk/channel-inbound";
import { saveMediaBuffer } from "openclaw/plugin-sdk/media-store";

import { NonAppendOnlyUpdateError } from "./append-only.js";
import { isRetryable, type MarmotAgentControlClient } from "./client.js";
import type { GroupActivation, StreamMode } from "./config.js";
import type { MarmotInboundMessage } from "./inbound.js";
import { MarmotLivePreview, type StreamControlClient } from "./live.js";
import { DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID } from "./runtime-state.js";
import { resolveLatestAssistantTextFromSessionStore } from "./session-transcript.js";

// --- reply sink (unit-tested) -----------------------------------------------

/** Kind of a streamed reply delivery from the OpenClaw reply dispatcher. */
export interface ReplyDelivery {
  kind: "final" | "block" | "tool";
}

/** The subset of the reply payload the Marmot sink reads. */
export interface ReplyPayloadLike {
  text?: string;
}

/** Partial assistant preview payload emitted before the durable reply dispatcher settles. */
export interface PartialReplyPayloadLike {
  text?: string;
  delta?: string;
  replace?: true;
}

export type MarmotSinkClient = Pick<MarmotAgentControlClient, "sendFinal"> & StreamControlClient;

export interface MarmotReplySinkOptions {
  client: MarmotSinkClient;
  accountIdHex: string;
  groupIdHex: string;
  replyToMessageIdHex?: string | null;
  streamMode: StreamMode;
  quicCandidates: string[];
  chunkBytes?: number;
  resolveFinalText?: () => Promise<string | undefined> | string | undefined;
  /** Optional privacy-safe lifecycle logger (kinds + lengths only, no content/ids). */
  log?: (message: string) => void;
}

const MIN_TRUNCATED_FINAL_PREFIX_CHARS = 48;
const MIN_TRUNCATED_FINAL_CONTINUATION_CHARS = 24;

function stripTrailingEllipsis(text: string): string {
  return text.replace(/(?:\s*(?:\.{3}|…))+$/u, "").trimEnd();
}

function isPotentialTruncatedFinal(text: string): boolean {
  const trimmed = text.trimEnd();
  const untruncated = stripTrailingEllipsis(trimmed);
  return untruncated.length >= MIN_TRUNCATED_FINAL_PREFIX_CHARS && untruncated !== trimmed;
}

function selectLongerFinalText(current: string, candidate: string | undefined): string | undefined {
  const candidateText = candidate?.trimEnd();
  if (!candidateText) {
    return undefined;
  }
  const currentText = current.trimEnd();
  if (!currentText) {
    return candidateText;
  }
  if (candidateText === currentText) {
    return currentText;
  }
  if (candidateText.length > currentText.length && candidateText.startsWith(currentText)) {
    return candidateText;
  }
  if (!isPotentialTruncatedFinal(currentText)) {
    return undefined;
  }
  const untruncated = stripTrailingEllipsis(currentText);
  if (candidateText.length <= currentText.length || !candidateText.startsWith(untruncated)) {
    return undefined;
  }
  const continuation = candidateText.slice(untruncated.length).trimStart();
  return continuation.length >= MIN_TRUNCATED_FINAL_CONTINUATION_CHARS && /^[\p{L}\p{N}]/u.test(continuation)
    ? candidateText
    : undefined;
}

/**
 * Maps the agent's streamed reply onto Marmot sends: progressive `block`
 * deliveries drive an append-only live QUIC preview; the `final` is committed
 * via `stream_finalize` when a preview is active and the final extends it, else
 * a plain `send_final`. A non-append-only update cancels the preview and falls
 * back to a verbatim `send_final` (mirrors the Hermes shim's behavior).
 */
export class MarmotReplySink {
  private preview: MarmotLivePreview | null = null;
  private previewAbandoned = false;
  /** Reply deliveries received from the dispatcher this turn (diagnostic). */
  deliveries = 0;
  /** Latest reconstructed answer text; used to commit a blocks-only turn at flush(). */
  private latestAnswerText = "";
  /** True once lower-latency partial snapshots, not delayed block chunks, own the preview. */
  private partialPreviewActive = false;
  /** True once OpenClaw has emitted any partial reply callback for this turn. */
  private sawPartialPreview = false;
  private partialDeliveries = 0;
  private partialAppendEvents = 0;
  private partialAppendedChars = 0;
  private loggedPartialStart = false;
  private loggedPartialAppendStart = false;
  private loggedPartialSummary = false;
  /** Whether the durable reply has been committed (stream_finalize or send_final). */
  private finalized = false;

  constructor(private readonly options: MarmotReplySinkOptions) {}

  private log(message: string): void {
    this.options.log?.(message);
  }

  private get streamingEnabled(): boolean {
    return this.options.streamMode !== "off" && this.options.quicCandidates.length > 0;
  }

  private ensurePreview(): MarmotLivePreview {
    if (!this.preview) {
      this.preview = new MarmotLivePreview(this.options.client, {
        accountIdHex: this.options.accountIdHex,
        groupIdHex: this.options.groupIdHex,
        quicCandidates: this.options.quicCandidates,
        chunkBytes: this.options.chunkBytes,
      });
    }
    return this.preview;
  }

  private async abandonPreview(reason: string): Promise<void> {
    this.previewAbandoned = true;
    if (this.preview) {
      // Best effort: if the QUIC stream is already unhealthy, cancel may also
      // fail — we still fall back to a plain durable send.
      await this.preview.cancel(reason).catch(() => undefined);
    }
  }

  private nextAnswerTextFromBlock(text: string): string {
    if (!this.latestAnswerText) {
      return text;
    }
    if (text.startsWith(this.latestAnswerText)) {
      return text;
    }
    if (this.latestAnswerText.endsWith(text)) {
      return this.latestAnswerText;
    }
    return `${this.latestAnswerText}${text}`;
  }

  private async bestFinalText(fallback: string): Promise<string> {
    let candidate: string | undefined;
    try {
      candidate = await this.options.resolveFinalText?.();
    } catch {
      this.log("marmot: transcript final recovery lookup failed");
    }
    if (!candidate?.trim()) {
      return fallback;
    }
    if (this.options.streamMode === "partial" || this.options.streamMode === "progress" || this.sawPartialPreview) {
      return candidate.trimEnd();
    }
    return selectLongerFinalText(fallback, candidate) ?? fallback;
  }

  private async sendProgress(text: string): Promise<void> {
    const progressText = text.trim();
    if (!progressText || !this.streamingEnabled || this.previewAbandoned) {
      return;
    }
    try {
      await this.ensurePreview().progress(progressText);
    } catch {
      this.log("marmot: live progress abandoned (preview_error); will send the final durably");
      await this.abandonPreview("preview_progress_error");
    }
  }

  async prewarm(): Promise<void> {
    if (!this.streamingEnabled || this.previewAbandoned) {
      return;
    }
    try {
      await this.ensurePreview().begin();
      this.log("marmot: live preview stream started");
    } catch {
      this.log("marmot: live preview start failed; will send the final durably");
      await this.abandonPreview("preview_begin_error");
    }
  }

  async status(status: string): Promise<void> {
    const statusText = status.trim();
    if (!statusText || !this.streamingEnabled || this.previewAbandoned) {
      return;
    }
    try {
      await this.ensurePreview().status(statusText);
    } catch {
      this.log("marmot: live status abandoned (preview_error); will send the final durably");
      await this.abandonPreview("preview_status_error");
    }
  }

  async progress(text: string): Promise<void> {
    await this.sendProgress(text);
  }

  async partial(payload: PartialReplyPayloadLike): Promise<void> {
    const text = String(payload.text ?? "");
    const delta = payload.replace === true ? "" : String(payload.delta ?? "");
    if (!text.trim() && delta.length === 0) {
      return;
    }
    this.sawPartialPreview = true;
    this.partialDeliveries += 1;
    if (!this.loggedPartialStart) {
      this.loggedPartialStart = true;
      this.log(
        `marmot: partial reply streaming started chars=${text.length} delta_chars=${delta.length} streaming=${this.streamingEnabled}`,
      );
    }
    if (!this.streamingEnabled || this.previewAbandoned) {
      this.latestAnswerText = text || `${this.latestAnswerText}${delta}`;
      return;
    }
    try {
      const preview = this.ensurePreview();
      if (delta.length > 0) {
        await preview.appendDelta(delta);
        this.partialPreviewActive = true;
        this.latestAnswerText = text || preview.currentText;
        this.notePartialAppend("delta", delta.length);
        return;
      }
      if (payload.replace === true) {
        this.log("marmot: skipped replacement partial without append delta");
        this.partialPreviewActive = false;
        return;
      }
      const previousLength = preview.currentText.length;
      await preview.update(text);
      this.partialPreviewActive = true;
      this.latestAnswerText = text;
      const appendedChars = preview.currentText.length - previousLength;
      if (appendedChars > 0) {
        this.notePartialAppend("snapshot", appendedChars);
      }
    } catch (error) {
      if (error instanceof NonAppendOnlyUpdateError) {
        this.log("marmot: skipped non-append partial without append delta");
        this.partialPreviewActive = false;
        return;
      }
      const reason = "preview_partial_error";
      this.log(`marmot: live partial preview abandoned (${reason}); will send the final durably`);
      this.partialPreviewActive = false;
      this.latestAnswerText = "";
      await this.abandonPreview(reason);
    }
  }

  private notePartialAppend(kind: "delta" | "snapshot", chars: number): void {
    this.partialAppendEvents += 1;
    this.partialAppendedChars += chars;
    if (!this.loggedPartialAppendStart) {
      this.loggedPartialAppendStart = true;
      this.log(`marmot: partial reply append started kind=${kind} chars=${chars}`);
    }
  }

  private logPartialSummary(): void {
    if (!this.sawPartialPreview || this.loggedPartialSummary) {
      return;
    }
    this.loggedPartialSummary = true;
    this.log(
      `marmot: partial reply summary deliveries=${this.partialDeliveries} appends=${this.partialAppendEvents} appended_chars=${this.partialAppendedChars}`,
    );
  }

  private async sendFinal(text: string): Promise<void> {
    this.log(`marmot: sending durable final (${text.length} chars)`);
    // One idempotency key for all attempts of THIS durable reply: a retry after a
    // post-write timeout reuses the key so the connector dedups instead of
    // double-posting an unrecallable encrypted message. Bounded retries with a
    // tiny backoff cover the transient/timeout window; non-retryable errors fail
    // fast and the last error is rethrown.
    const idempotencyKey = randomUUID();
    const backoffMs = [100, 300];
    let attempt = 0;
    for (;;) {
      try {
        await this.options.client.sendFinal(
          this.options.accountIdHex,
          this.options.groupIdHex,
          text,
          this.options.replyToMessageIdHex ?? null,
          idempotencyKey,
        );
        this.log("marmot: durable final sent");
        return;
      } catch (err) {
        if (attempt >= backoffMs.length || !isRetryable(err)) {
          throw err;
        }
        this.log(`marmot: durable final send failed; retrying (attempt ${attempt + 1})`);
        await new Promise((resolve) => setTimeout(resolve, backoffMs[attempt]));
        attempt += 1;
      }
    }
  }

  async deliver(payload: ReplyPayloadLike, info: ReplyDelivery): Promise<void> {
    const text = payload?.text ?? "";
    this.deliveries += 1;
    this.log(
      `marmot: reply delivery kind=${info.kind} chars=${text.length} streaming=${this.streamingEnabled}`,
    );

    if (info.kind === "tool") {
      await this.sendProgress(text);
      return;
    }

    if (info.kind === "block") {
      if (this.partialPreviewActive) {
        // OpenClaw emits delayed block chunks after earlier partial snapshots.
        // Once partials own the live preview, blocks are only a durable fallback;
        // appending them would replay or reorder already-streamed text.
        return;
      }
      this.latestAnswerText = this.nextAnswerTextFromBlock(text);
      if (!this.streamingEnabled || this.previewAbandoned) {
        return; // recorded in latestAnswerText; committed by the final delivery or flush()
      }
      try {
        await this.ensurePreview().update(this.latestAnswerText);
      } catch (error) {
        // Any preview failure — non-append-only text, or a QUIC/broker error —
        // abandons the live preview. The full text is still delivered durably by
        // the final delivery or flush(), so a streaming hiccup never drops it.
        const reason =
          error instanceof NonAppendOnlyUpdateError ? "non_append_only" : "preview_error";
        this.log(`marmot: live preview abandoned (${reason}); will send the final durably`);
        await this.abandonPreview(reason);
      }
      return;
    }

    this.latestAnswerText = text || this.latestAnswerText;
    await this.commit(this.latestAnswerText);
  }

  /**
   * Commit the durable reply exactly once: finalize an active live preview into
   * a stream-final, otherwise send a plain durable final.
   */
  private async commit(text: string): Promise<boolean> {
    if (this.finalized) {
      return true;
    }
    const finalText = await this.bestFinalText(text);
    if (!finalText) {
      return false;
    }
    this.finalized = true;
    this.logPartialSummary();
    if (this.preview && this.preview.isActive && !this.previewAbandoned) {
      try {
        await this.preview.finalize(finalText);
        this.log(`marmot: live preview finalized (${finalText.length} chars)`);
        return true;
      } catch (error) {
        const reason =
          error instanceof NonAppendOnlyUpdateError ? "final_not_append_only" : "finalize_error";
        this.log(`marmot: preview finalize failed (${reason}); falling back to a durable send`);
        await this.abandonPreview(reason);
      }
    }
    await this.sendFinal(finalText);
    return true;
  }

  /**
   * Commit the reply once the agent turn has finished. Block streaming can
   * deliver the whole reply as `block`s with no trailing `final`; without this
   * the live preview would never be finalized and no durable kind:9 would land.
   * A no-op once a `final` delivery already committed, or if the turn produced
   * no text at all.
   */
  async flush(): Promise<void> {
    if (this.finalized) {
      return;
    }
    this.log("marmot: no explicit final delivery; committing the streamed reply at turn end");
    if (this.options.streamMode === "block" && this.sawPartialPreview && this.deliveries === 0) {
      this.log("marmot: no block/final reply deliveries; abandoning partial-only block preview");
      if (this.preview?.isActive) {
        await this.abandonPreview("no_deliverable_reply");
      }
      return;
    }
    if (await this.commit(this.latestAnswerText)) {
      return;
    }
    if (!this.latestAnswerText) {
      this.log("marmot: turn produced no deliverable reply");
      if (this.preview?.isActive) {
        await this.abandonPreview("no_deliverable_reply");
      }
      return;
    }
  }
}

// --- inbound turn dispatch (SDK-coupled; harness-validated) ------------------

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
 * Dispatcher client: the reply sink surface plus the group-info read for
 * gating and the media download used to surface inbound images to the agent.
 */
export type MarmotDispatchClient = MarmotSinkClient &
  Pick<MarmotAgentControlClient, "groupInfo" | "downloadMedia">;

export interface MarmotDispatchDeps {
  /** Full OpenClaw config (`api.config`). */
  cfg: unknown;
  /** `api.runtime.channel`. */
  runtimeChannel: OpenClawChannelRuntime;
  client: MarmotDispatchClient;
  /** OpenClaw channel account id ("default" or a configured account key), not the Marmot account hex. */
  channelAccountId?: string | null;
  streamMode: StreamMode;
  blockStreaming: boolean;
  quicCandidates: string[];
  chunkBytes?: number;
  /** When to reply in a multi-party group ("mention" gates; "always" replies to all). */
  groupActivation: GroupActivation;
  /** Case-insensitive trigger phrases that count as addressing the agent. */
  mentionPatterns: string[];
  /** Optional privacy-safe lifecycle logger. */
  log?: (message: string) => void;
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
 * invalidates an entry when dm-agent reports a `group_state_changed` event for
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
 * when addressed (agent p-tagged, a trigger matches) or in an effective DM
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
 * Best-effort: download each inbound media ref to a local path on the dm-agent
 * host, then re-stage the decrypted bytes through OpenClaw's official media store
 * so the resulting path is under an allowlisted media root. Native vision trusts
 * the path directly, but the agent's `image` tool enforces an allowlist
 * (`assertLocalMediaAllowed`) whose roots are OpenClaw's media dir — the raw
 * dm-agent temp path is not under them, so the tool would reject it. Building the
 * `InboundMediaFacts` from the staged path keeps both paths working. The dm-agent
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
    // Captured so the dm-agent temp file is unlinked even if readFile or
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
      // The dm-agent temp file is redundant once re-staged (or unusable on a
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
 * kernel, delivering the agent's reply through a per-message MarmotReplySink.
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
    // local path (dm-agent decrypts; the content key never leaves it) and hand
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
    const dispatchStartedAt = Date.now();
    const sink = new MarmotReplySink({
      client: deps.client,
      accountIdHex: message.accountIdHex,
      groupIdHex: message.groupIdHex,
      // Thread the reply to the triggering message (channel declares
      // topLevelReplyToMode "reply"). Honored by the durable send_final path;
      // the streaming finalize path threads in a later phase.
      replyToMessageIdHex: message.messageIdHex,
      streamMode: deps.streamMode,
      quicCandidates: deps.quicCandidates,
      chunkBytes: deps.chunkBytes,
      resolveFinalText: () =>
        resolveLatestAssistantTextFromSessionStore({
          storePath,
          sessionKey: route.sessionKey,
          startedAtMs: dispatchStartedAt,
        }),
      log: deps.log,
    });

    deps.log?.("marmot: agent turn starting");
    await sink.prewarm();
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
              cfg: deps.cfg,
              dispatcherOptions: {
                deliver: (payload: ReplyPayloadLike, info: ReplyDelivery) =>
                  sink.deliver(payload, info),
              },
              replyOptions: {
                disableBlockStreaming: deps.blockStreaming ? false : true,
                onPartialReply: (payload: PartialReplyPayloadLike) => sink.partial(payload),
                onAssistantMessageStart: () => sink.status("Thinking..."),
                onRunProgress: () => sink.status("Working..."),
                onExecutionPhase: (info: { phase?: string; firstModelCallStarted?: boolean }) => {
                  if (info.firstModelCallStarted || info.phase === "model_call_started") {
                    return sink.status("Thinking...");
                  }
                  return undefined;
                },
                onToolStart: () => sink.progress("Working..."),
                onCommandOutput: () => sink.progress("Working..."),
              },
            }) as never,
        }),
      },
    });
    // Block streaming can finish a turn with only `block` deliveries; commit the
    // accumulated reply durably if no explicit `final` did.
    await sink.flush();
    deps.log?.(`marmot: agent turn done (sink deliveries=${sink.deliveries})`);
  };

  return Object.assign(dispatch, {
    invalidateGroupActivation: (accountIdHex: string, groupIdHex: string) =>
      activationCache.invalidate(accountIdHex, groupIdHex),
    clearGroupActivationCache: () => activationCache.clear(),
  });
}
