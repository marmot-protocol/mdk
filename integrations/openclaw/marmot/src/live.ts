// Live-preview state machine bridging OpenClaw progressive draft updates to
// Marmot's QUIC preview stream + durable finalize.
//
// OpenClaw hands us growing full-text snapshots (draft-stream `update(text)`);
// we reduce each to an append-only suffix, mirror it into a local transcript
// (byte-for-byte with dm-agent's), and send `stream_append`. On finalize we send
// the transcript hash + chunk count dm-agent validates against its own. A
// non-append-only update throws so the caller can cancel + send a plain final.

import { AppendOnlyText, NonAppendOnlyUpdateError } from "./append-only.js";
import type { MarmotAgentControlClient } from "./client.js";
import { AgentTextStreamTranscript, DEFAULT_STREAM_CHUNK_BYTES } from "./transcript.js";

/** Narrow control-client surface used by the live preview (eases testing). */
export type StreamControlClient = Pick<
  MarmotAgentControlClient,
  "streamBegin" | "streamAppend" | "streamStatus" | "streamProgress" | "streamFinalize" | "streamCancel"
>;

export interface MarmotLivePreviewOptions {
  accountIdHex: string;
  groupIdHex: string;
  quicCandidates: string[];
  chunkBytes?: number;
}

export interface MarmotLiveFinalizeResult {
  streamIdHex: string;
  startMessageIdHex: string;
  messageIdsHex: string[];
}

export class MarmotLivePreview {
  private begun = false;
  private beginPromise: Promise<void> | null = null;
  private closed = false;
  private streamIdHex: string | null = null;
  private startMessageIdHex: string | null = null;
  private transcript: AgentTextStreamTranscript | null = null;
  private readonly appendOnly = new AppendOnlyText();
  private readonly chunkBytes: number;

  constructor(
    private readonly client: StreamControlClient,
    private readonly options: MarmotLivePreviewOptions,
  ) {
    this.chunkBytes = options.chunkBytes ?? DEFAULT_STREAM_CHUNK_BYTES;
  }

  get streamId(): string | null {
    return this.streamIdHex;
  }

  get isActive(): boolean {
    return this.begun && !this.closed;
  }

  get currentText(): string {
    return this.appendOnly.current;
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new Error("live preview is already finalized or cancelled");
    }
  }

  private async ensureBegun(): Promise<void> {
    if (this.begun) {
      return;
    }
    // Guard against concurrent first calls (e.g. a `status` racing a `partial`
    // before any `begin()`/`prewarm()`): the first caller starts the remote
    // begin and stashes the in-flight promise; subsequent callers await the
    // same promise instead of issuing a second `stream_begin`. On failure the
    // promise is cleared so a later call can retry the begin.
    if (this.beginPromise) {
      await this.beginPromise;
      return;
    }
    this.beginPromise = this.beginStream();
    try {
      await this.beginPromise;
    } catch (error) {
      this.beginPromise = null;
      throw error;
    }
  }

  private async beginStream(): Promise<void> {
    const response = await this.client.streamBegin(
      this.options.accountIdHex,
      this.options.groupIdHex,
      { quicCandidates: this.options.quicCandidates },
    );
    this.streamIdHex = response.stream_id_hex;
    this.startMessageIdHex = response.start_message_id_hex;
    this.transcript = new AgentTextStreamTranscript(
      Buffer.from(response.stream_id_hex, "hex"),
      Buffer.from(response.start_message_id_hex, "hex"),
    );
    this.begun = true;
  }

  /**
   * Start the remote stream early without appending transcript records. This
   * gives clients time to discover the stream-start event and subscribe before
   * model text arrives.
   */
  async begin(): Promise<void> {
    this.ensureOpen();
    await this.ensureBegun();
    this.ensureOpen();
  }

  /**
   * Push the latest full preview text. Throws {@link NonAppendOnlyUpdateError}
   * if it is not an extension of what was already streamed.
   */
  async update(fullText: string): Promise<void> {
    this.ensureOpen();
    await this.ensureBegun();
    this.ensureOpen();
    const current = this.appendOnly.current;
    if (!fullText.startsWith(current)) {
      throw new NonAppendOnlyUpdateError();
    }
    const suffix = fullText.slice(current.length);
    if (suffix.length === 0) {
      return;
    }
    // Commit local transcript/append state only after the remote append
    // succeeds, so a failed append can be retried with the same text without
    // diverging from dm-agent's transcript.
    await this.client.streamAppend(this.streamIdHex!, suffix);
    this.transcript!.appendText(suffix, this.chunkBytes);
    this.appendOnly.suffixFor(fullText);
  }

  async appendDelta(delta: string): Promise<void> {
    this.ensureOpen();
    await this.ensureBegun();
    this.ensureOpen();
    const suffix = String(delta ?? "");
    if (suffix.length === 0) {
      return;
    }
    const next = `${this.appendOnly.current}${suffix}`;
    await this.client.streamAppend(this.streamIdHex!, suffix);
    this.transcript!.appendText(suffix, this.chunkBytes);
    this.appendOnly.suffixFor(next);
  }

  async status(status: string): Promise<void> {
    this.ensureOpen();
    const text = String(status ?? "");
    if (text.length === 0) {
      return;
    }
    await this.ensureBegun();
    this.ensureOpen();
    await this.client.streamStatus(this.streamIdHex!, text);
    this.transcript!.appendStatus(text, this.chunkBytes);
  }

  async progress(text: string): Promise<void> {
    this.ensureOpen();
    const progressText = String(text ?? "");
    if (progressText.length === 0) {
      return;
    }
    await this.ensureBegun();
    this.ensureOpen();
    await this.client.streamProgress(this.streamIdHex!, progressText);
    this.transcript!.appendProgress(progressText, this.chunkBytes);
  }

  /**
   * Append the remaining suffix (if any) and finalize the durable kind-9.
   * Throws {@link NonAppendOnlyUpdateError} if `finalText` is not an extension
   * of the streamed text.
   */
  async finalize(finalText: string): Promise<MarmotLiveFinalizeResult> {
    this.ensureOpen();
    await this.ensureBegun();
    this.ensureOpen();
    const current = this.appendOnly.current;
    if (!finalText.startsWith(current)) {
      throw new NonAppendOnlyUpdateError();
    }
    const suffix = finalText.slice(current.length);
    if (suffix.length > 0) {
      await this.client.streamAppend(this.streamIdHex!, suffix);
      this.transcript!.appendText(suffix, this.chunkBytes);
      this.appendOnly.suffixFor(finalText);
    }
    const response = await this.client.streamFinalize(
      this.streamIdHex!,
      finalText,
      this.transcript!.hashHex,
      this.transcript!.chunkCount,
    );
    this.closed = true;
    return {
      streamIdHex: this.streamIdHex!,
      startMessageIdHex: this.startMessageIdHex!,
      messageIdsHex: response.message_ids_hex,
    };
  }

  /**
   * Cancel the live preview (best-effort) and mark it terminal. Idempotent;
   * a no-op if already finalized/cancelled or never begun.
   */
  async cancel(reason?: string): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    // `closed` is set before awaiting an in-flight begin so every post-begin
    // continuation re-checks terminal state before dispatching its first remote
    // write. A write already inside client.stream* may still land; stream_cancel
    // is the best-effort terminal signal for that pre-existing window.
    const pendingBegin = this.beginPromise;
    if (pendingBegin) {
      try {
        await pendingBegin;
      } catch {
        return;
      }
    }
    if (!this.begun || !this.streamIdHex) {
      return;
    }
    await this.client.streamCancel(this.streamIdHex, reason ?? null);
  }
}
