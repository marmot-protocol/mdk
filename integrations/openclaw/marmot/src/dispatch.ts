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

import {
  buildChannelInboundEventContext,
  runChannelInboundEvent,
} from "openclaw/plugin-sdk/channel-inbound";

import { NonAppendOnlyUpdateError } from "./append-only.js";
import type { MarmotAgentControlClient } from "./client.js";
import type { StreamMode } from "./config.js";
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
    await this.options.client.sendFinal(
      this.options.accountIdHex,
      this.options.groupIdHex,
      text,
      this.options.replyToMessageIdHex ?? null,
    );
    this.log("marmot: durable final sent");
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

export interface MarmotDispatchDeps {
  /** Full OpenClaw config (`api.config`). */
  cfg: unknown;
  /** `api.runtime.channel`. */
  runtimeChannel: OpenClawChannelRuntime;
  client: MarmotSinkClient;
  /** OpenClaw channel account id ("default" or a configured account key), not the Marmot account hex. */
  channelAccountId?: string | null;
  streamMode: StreamMode;
  blockStreaming: boolean;
  quicCandidates: string[];
  chunkBytes?: number;
  /** Optional privacy-safe lifecycle logger. */
  log?: (message: string) => void;
}

/**
 * Build the inbound dispatcher: for each received Marmot message, resolve the
 * agent route, build the inbound context, and run it through the OpenClaw turn
 * kernel, delivering the agent's reply through a per-message MarmotReplySink.
 */
export function createMarmotInboundDispatcher(
  deps: MarmotDispatchDeps,
): (message: MarmotInboundMessage) => Promise<void> {
  return async (message) => {
    const channelAccountId = deps.channelAccountId?.trim() || DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
    const route = deps.runtimeChannel.routing.resolveAgentRoute({
      cfg: deps.cfg,
      channel: "marmot",
      accountId: channelAccountId,
      peer: { kind: "group", id: message.groupIdHex },
    });

    const ctxPayload = buildChannelInboundEventContext({
      channel: "marmot",
      accountId: channelAccountId,
      messageId: message.messageIdHex,
      from: message.senderAccountIdHex,
      sender: { id: message.senderAccountIdHex },
      conversation: { kind: "group", id: message.groupIdHex },
      route: {
        agentId: route.agentId,
        accountId: route.accountId,
        routeSessionKey: route.sessionKey,
      },
      reply: { to: message.groupIdHex },
      message: { rawBody: message.text, bodyForAgent: message.text },
    });

    const storePath = deps.runtimeChannel.session.resolveStorePath();
    const dispatchStartedAt = Date.now();
    const sink = new MarmotReplySink({
      client: deps.client,
      accountIdHex: message.accountIdHex,
      groupIdHex: message.groupIdHex,
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
}
