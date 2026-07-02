// TypeScript client for the `marmot.agent-control.v1` control protocol
// (`crates/agent-control/src/lib.rs`). Newline-delimited JSON over a local Unix
// socket. Faithful port of the Python `MarmotAgentControlClient`
// (`integrations/hermes/marmot/adapter.py`): one connection per request with
// id correlation, and a single long-lived connection for `subscribe_inbound`
// that streams events until EOF.
//
// Privacy: never log account ids, group ids, message ids, pubkeys, relay URLs,
// payloads, ciphertext, plaintext, or key material.

import { createConnection, type Socket } from "node:net";
import { randomUUID } from "node:crypto";

export const AGENT_CONTROL_PROTOCOL_V1 = "marmot.agent-control.v1";
export const MAX_AGENT_CONTROL_FRAME_BYTES = 1024 * 1024;

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
// Live-preview side-channel ops (stream begin/append/status/progress/cancel) are
// best-effort: they only drive the QUIC typing preview, while the durable kind-9
// is committed separately via send_final / stream_finalize. Bounding them well
// below the full request timeout means a wedged broker abandons the preview in a
// few seconds instead of pinning the agent turn — and the shared execution-lane
// slot it holds — for the full 30s per op. The durable ops keep
// DEFAULT_REQUEST_TIMEOUT_MS so a slow-but-live commit is never abandoned into a
// duplicate send.
const DEFAULT_PREVIEW_REQUEST_TIMEOUT_MS = 8_000;

export class AgentControlError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(
    message: string,
    options: { code?: string; retryable?: boolean; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "AgentControlError";
    this.code = options.code ?? "agent_control_error";
    this.retryable = options.retryable ?? false;
  }
}

export function isRetryable(err: unknown): boolean {
  return err instanceof AgentControlError && err.retryable;
}

export interface AgentControlAccount {
  account_id_hex: string;
  label: string;
  local_signing: boolean;
}

export interface AccountListResponse {
  type: "account_list";
  accounts: AgentControlAccount[];
}

export interface FinalSentResponse {
  type: "final_sent";
  message_ids_hex: string[];
}

export interface AppEventSentResponse {
  type: "app_event_sent";
  message_ids_hex: string[];
}

export interface StreamBegunResponse {
  type: "stream_begun";
  stream_id_hex: string;
  start_message_id_hex: string;
  quic_candidates: string[];
}

export interface StreamFinalizedResponse {
  type: "stream_finalized";
  stream_id_hex: string;
  message_ids_hex: string[];
}

export interface AllowlistResponse {
  type: "allowlist";
  account_id_hex: string;
  welcomer_account_ids_hex: string[];
}

export interface GroupInfoResponse {
  type: "group_info";
  account_id_hex: string;
  group_id_hex: string;
  member_count: number;
  /** True when the group has exactly two members (effective DM; always reply). */
  is_direct: boolean;
  subject?: string | null;
}

export interface ProfilePublishedResponse {
  type: "profile_published";
  account_id_hex: string;
  name: string;
  display_name: string | null;
}

/** A single fetch locator for an encrypted media reference. */
export interface AgentControlMediaLocator {
  kind: string;
  value: string;
}

/**
 * Faithful, non-secret mirror of the Rust `MediaAttachmentReference`. Carries
 * everything needed to fetch + authenticate an encrypted blob EXCEPT the content
 * key, which never leaves `dm-agent`. Pass it back to {@link MarmotAgentControlClient.downloadMedia}.
 */
export interface AgentControlMediaRef {
  media_type: string;
  file_name: string;
  ciphertext_sha256: string;
  plaintext_sha256: string;
  nonce_hex: string;
  version: string;
  source_epoch: number;
  locators: AgentControlMediaLocator[];
  dim?: string | null;
  thumbhash?: string | null;
}

/**
 * A local file for {@link MarmotAgentControlClient.sendMedia} to encrypt + upload
 * as an attachment. `dm-agent` reads the bytes from `path` on its own host; the
 * control plane never carries plaintext or a content key.
 */
export interface AgentControlMediaUpload {
  path: string;
  media_type: string;
  file_name: string;
  dim?: string | null;
  thumbhash?: string | null;
}

export interface MediaDownloadedResponse {
  type: "media_downloaded";
  /** Host-local path on the `dm-agent` machine where the plaintext was written. */
  path: string;
  media_type: string;
  file_name: string;
  size_bytes: number;
}

export type AgentControlEvent =
  | {
      type: "inbound_message";
      account_id_hex: string;
      group_id_hex: string;
      message_id_hex: string;
      sender_account_id_hex: string;
      text: string;
      /**
       * True when the message addresses the agent via p-tag, nostr hex, or
       * visible npub mention.
       */
      mentions_self?: boolean;
      /** The message id this message replies to (`e` tag), when present. */
      reply_to_message_id_hex?: string | null;
      /** Sender's directory display name, when resolvable. */
      sender_display_name?: string | null;
      /** Encrypted media references (`imeta` tags) on this message, if any. */
      media?: AgentControlMediaRef[];
    }
  | {
      type: "message_deleted";
      account_id_hex: string;
      group_id_hex: string;
      target_message_id_hex: string;
      sender_account_id_hex: string;
    }
  | {
      type: "group_state_changed";
      account_id_hex: string;
      group_id_hex: string;
      /**
       * Coarse change kind: "member_added" | "member_removed" | "member_left" |
       * "admin_added" | "admin_removed" | "group_renamed" | "group_avatar_changed".
       * Privacy: never carries a member pubkey.
       */
      change: string;
      /** New group display name for "group_renamed"; absent otherwise. */
      detail?: string | null;
    }
  | {
      type: "group_invite";
      account_id_hex: string;
      group_id_hex: string;
      via_welcome_message_id_hex: string;
      welcomer_account_id_hex: string | null;
    }
  | {
      type: "stream_update";
      account_id_hex: string;
      group_id_hex: string;
      stream_id_hex: string;
      status: string;
    }
  | {
      type: "resync_required";
      account_id_hex: string | null;
      group_id_hex: string | null;
      dropped_events: number;
    };

export interface MarmotAgentControlClientOptions {
  socketPath: string;
  authToken?: string | undefined;
  requestTimeoutMs?: number;
  /**
   * Timeout for best-effort live-preview ops (stream begin/append/status/progress/
   * cancel). Defaults to {@link DEFAULT_PREVIEW_REQUEST_TIMEOUT_MS}; kept short so a
   * wedged preview broker abandons the preview quickly rather than holding the agent
   * turn open. Durable ops (send_final, stream_finalize) always use requestTimeoutMs.
   */
  previewRequestTimeoutMs?: number;
}

interface RequestOptions {
  requestId?: string;
  timeoutMs?: number;
}

interface SubscribeInboundHooks {
  onReady?: () => void;
}

type Envelope = Record<string, unknown>;

/** Lowercase, strip an optional `0x`, and validate even-length hexadecimal. */
export function normalizeHex(value: string | null | undefined, field = "hex"): string {
  let text = String(value ?? "").trim().toLowerCase();
  if (text.startsWith("0x")) {
    text = text.slice(2);
  }
  if (text.length === 0) {
    throw new AgentControlError(`${field} must not be empty`, { code: "invalid_hex" });
  }
  if (text.length % 2 !== 0 || !/^[0-9a-f]+$/.test(text)) {
    throw new AgentControlError(`${field} must be hexadecimal`, { code: "invalid_hex" });
  }
  return text;
}

function optionalHex(value: string | null | undefined, field = "hex"): string | null {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }
  return normalizeHex(value, field);
}

export class MarmotAgentControlClient {
  readonly socketPath: string;
  private readonly authToken: string | null;
  private readonly requestTimeoutMs: number;
  private readonly previewRequestTimeoutMs: number;

  constructor(options: MarmotAgentControlClientOptions) {
    this.socketPath = options.socketPath;
    const token = options.authToken?.trim();
    this.authToken = token ? token : null;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.previewRequestTimeoutMs =
      options.previewRequestTimeoutMs ?? DEFAULT_PREVIEW_REQUEST_TIMEOUT_MS;
  }

  // --- typed request helpers --------------------------------------------------

  async accountList(): Promise<AccountListResponse> {
    return (await this.request({ type: "account_list" })) as unknown as AccountListResponse;
  }

  async accountPublishProfile(
    accountIdHex: string,
    name: string,
    displayName?: string | null,
  ): Promise<ProfilePublishedResponse> {
    return (await this.request({
      type: "account_publish_profile",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      name: String(name ?? ""),
      display_name: displayName == null ? null : String(displayName),
    })) as unknown as ProfilePublishedResponse;
  }

  async sendFinal(
    accountIdHex: string,
    groupIdHex: string,
    text: string,
    replyToMessageIdHex?: string | null,
    idempotencyKey?: string,
  ): Promise<FinalSentResponse> {
    const key = idempotencyKey?.trim();
    return (await this.request({
      type: "send_final",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
      text: String(text ?? ""),
      reply_to_message_id_hex: optionalHex(replyToMessageIdHex, "reply_to_message_id_hex"),
      // Additive, v1-compatible: only sent when supplied, so the connector dedups
      // a retry that reuses the same key instead of double-posting.
      ...(key ? { idempotency_key: key } : {}),
    })) as unknown as FinalSentResponse;
  }

  /** Delete (retract) a previously-sent group message; emits a kind-5 deletion. */
  async deleteMessage(
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
  ): Promise<FinalSentResponse> {
    return (await this.request({
      type: "delete_message",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
      target_message_id_hex: normalizeHex(targetMessageIdHex, "target_message_id_hex"),
    })) as unknown as FinalSentResponse;
  }

  async streamBegin(
    accountIdHex: string,
    groupIdHex: string,
    options: { streamIdHex?: string | null; quicCandidates?: Iterable<string> } = {},
  ): Promise<StreamBegunResponse> {
    const quicCandidates = [...(options.quicCandidates ?? [])]
      .map((candidate) => String(candidate).trim())
      .filter((candidate) => candidate.length > 0);
    return (await this.request(
      {
        type: "stream_begin",
        account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
        group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
        stream_id_hex: optionalHex(options.streamIdHex, "stream_id_hex"),
        quic_candidates: quicCandidates,
      },
      { timeoutMs: this.previewRequestTimeoutMs },
    )) as unknown as StreamBegunResponse;
  }

  async streamAppend(streamIdHex: string, appendText: string): Promise<Envelope> {
    return this.request(
      {
        type: "stream_append",
        stream_id_hex: normalizeHex(streamIdHex, "stream_id_hex"),
        append_text: String(appendText ?? ""),
      },
      { timeoutMs: this.previewRequestTimeoutMs },
    );
  }

  async streamStatus(streamIdHex: string, status: string): Promise<Envelope> {
    return this.request(
      {
        type: "stream_status",
        stream_id_hex: normalizeHex(streamIdHex, "stream_id_hex"),
        status: String(status ?? ""),
      },
      { timeoutMs: this.previewRequestTimeoutMs },
    );
  }

  async streamProgress(streamIdHex: string, text: string): Promise<Envelope> {
    return this.request(
      {
        type: "stream_progress",
        stream_id_hex: normalizeHex(streamIdHex, "stream_id_hex"),
        text: String(text ?? ""),
      },
      { timeoutMs: this.previewRequestTimeoutMs },
    );
  }

  async streamFinalize(
    streamIdHex: string,
    finalText: string,
    transcriptHashHex: string,
    chunkCount: number,
  ): Promise<StreamFinalizedResponse> {
    // Durable commit: keep the full request timeout. Abandoning a live finalize
    // early could re-send via send_final and duplicate the kind-9, so this op is
    // intentionally not bounded by previewRequestTimeoutMs.
    return (await this.request({
      type: "stream_finalize",
      stream_id_hex: normalizeHex(streamIdHex, "stream_id_hex"),
      final_text: String(finalText ?? ""),
      transcript_hash_hex: normalizeHex(transcriptHashHex, "transcript_hash_hex"),
      chunk_count: Math.trunc(chunkCount),
    })) as unknown as StreamFinalizedResponse;
  }

  async streamCancel(streamIdHex: string, reason?: string | null): Promise<Envelope> {
    return this.request(
      {
        type: "stream_cancel",
        stream_id_hex: normalizeHex(streamIdHex, "stream_id_hex"),
        reason: reason == null ? null : String(reason),
      },
      { timeoutMs: this.previewRequestTimeoutMs },
    );
  }

  async allowlistList(accountIdHex: string): Promise<AllowlistResponse> {
    return (await this.request({
      type: "allowlist_list",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
    })) as unknown as AllowlistResponse;
  }

  /** Group membership for activation policy (member count, is_direct, subject). */
  async groupInfo(accountIdHex: string, groupIdHex: string): Promise<GroupInfoResponse> {
    return (await this.request({
      type: "group_info",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
    })) as unknown as GroupInfoResponse;
  }

  async allowlistAdd(
    accountIdHex: string,
    welcomerAccountIdHex: string,
  ): Promise<Envelope> {
    return this.request({
      type: "allowlist_add",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      welcomer_account_id_hex: normalizeHex(welcomerAccountIdHex, "welcomer_account_id_hex"),
    });
  }

  async allowlistRemove(
    accountIdHex: string,
    welcomerAccountIdHex: string,
  ): Promise<Envelope> {
    return this.request({
      type: "allowlist_remove",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      welcomer_account_id_hex: normalizeHex(welcomerAccountIdHex, "welcomer_account_id_hex"),
    });
  }

  async sendAgentOperationEvent(
    accountIdHex: string,
    groupIdHex: string,
    event: {
      eventType: string;
      status: string;
      text?: string;
      name?: string | null;
      operationId?: string | null;
      runId?: string | null;
      turnId?: string | null;
      preview?: string | null;
      details?: unknown;
      sequence?: number | null;
      ok?: boolean | null;
      durationMs?: number | null;
      replyToMessageIdHex?: string | null;
    },
  ): Promise<AppEventSentResponse> {
    return (await this.request({
      type: "send_agent_operation_event",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
      event_type: String(event.eventType ?? ""),
      status: String(event.status ?? ""),
      operation_id: event.operationId ? String(event.operationId).trim() : null,
      run_id: event.runId ? String(event.runId).trim() : null,
      turn_id: event.turnId ? String(event.turnId).trim() : null,
      name: event.name ? String(event.name).trim() : null,
      text: String(event.text ?? ""),
      preview: event.preview == null ? null : String(event.preview),
      details: event.details ?? null,
      sequence: event.sequence == null ? null : Math.trunc(event.sequence),
      ok: event.ok == null ? null : Boolean(event.ok),
      duration_ms: event.durationMs == null ? null : Math.trunc(event.durationMs),
      reply_to_message_id_hex: optionalHex(event.replyToMessageIdHex, "reply_to_message_id_hex"),
    })) as unknown as AppEventSentResponse;
  }

  /**
   * Encrypt + upload local files as encrypted media and send them as a kind-9
   * message in the group. `dm-agent` reads each file's bytes from its host by
   * `path`; the control plane never carries plaintext or a content key. Returns
   * the durable message ids (`final_sent`).
   */
  async sendMedia(
    accountIdHex: string,
    groupIdHex: string,
    attachments: AgentControlMediaUpload[],
    caption?: string | null,
  ): Promise<FinalSentResponse> {
    return (await this.request({
      type: "send_media",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
      attachments,
      caption: caption == null ? null : String(caption),
    })) as unknown as FinalSentResponse;
  }

  /**
   * Fetch + decrypt an inbound media reference and write the plaintext to a temp
   * file on the `dm-agent` host. The content key stays in `dm-agent`; the reply
   * carries only the host-local path and metadata (`media_downloaded`).
   */
  async downloadMedia(
    accountIdHex: string,
    groupIdHex: string,
    media: AgentControlMediaRef,
  ): Promise<MediaDownloadedResponse> {
    return (await this.request({
      type: "download_media",
      account_id_hex: normalizeHex(accountIdHex, "account_id_hex"),
      group_id_hex: normalizeHex(groupIdHex, "group_id_hex"),
      media,
    })) as unknown as MediaDownloadedResponse;
  }

  // --- inbound subscription ---------------------------------------------------

  /**
   * Open a long-lived `subscribe_inbound` connection and yield control events
   * until the connector closes the stream (EOF) or an error occurs. The caller
   * is responsible for reconnecting; a `resync_required` event signals that the
   * connector dropped events on broadcast lag and the agent must re-sync.
   */
  async *subscribeInbound(
    filter: { accountIdHex?: string | null; groupIdHex?: string | null } = {},
    signal?: AbortSignal,
    hooks: SubscribeInboundHooks = {},
  ): AsyncGenerator<AgentControlEvent> {
    const requestId = randomUUID();
    const socket = await this.connect();
    // Tear down the socket on abort so a blocked read (idle subscription) ends
    // promptly instead of waiting for the next frame or a disconnect.
    const onAbort = () => socket.destroy();
    if (signal?.aborted) {
      socket.destroy();
    } else {
      signal?.addEventListener("abort", onAbort, { once: true });
    }
    let ackTimer: NodeJS.Timeout | undefined = setTimeout(() => {
      socket.destroy(
        new AgentControlError("timed out waiting for subscribe ack", {
          code: "timeout",
          retryable: true,
        }),
      );
    }, this.requestTimeoutMs);
    try {
      await this.writeEnvelope(socket, requestId, {
        type: "subscribe_inbound",
        account_id_hex: optionalHex(filter.accountIdHex, "account_id_hex"),
        group_id_hex: optionalHex(filter.groupIdHex, "group_id_hex"),
      });
      let acked = false;
      for await (const frame of readFrames(socket)) {
        validateEnvelope(frame, requestId);
        raiseIfError(frame);
        if (!acked) {
          if (frame.type !== "ack") {
            throw new AgentControlError(
              `expected subscribe ack, got ${String(frame.type)}`,
              { code: "wrong_protocol" },
            );
          }
          acked = true;
          if (ackTimer) {
            clearTimeout(ackTimer);
            ackTimer = undefined;
          }
          hooks.onReady?.();
          continue;
        }
        yield frame as unknown as AgentControlEvent;
      }
    } catch (err) {
      throw wrapSocketError(err);
    } finally {
      if (ackTimer) {
        clearTimeout(ackTimer);
      }
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
    }
  }

  // --- low-level request ------------------------------------------------------

  async request(payload: Envelope, options: RequestOptions = {}): Promise<Envelope> {
    const requestId = options.requestId ?? randomUUID();
    const timeoutMs = options.timeoutMs ?? this.requestTimeoutMs;
    const socket = await this.connect(timeoutMs);
    const deadline = setTimeout(() => {
      socket.destroy(
        new AgentControlError("timed out waiting for agent control response", {
          code: "timeout",
          retryable: true,
        }),
      );
    }, timeoutMs);
    try {
      await this.writeEnvelope(socket, requestId, payload);
      for await (const frame of readFrames(socket)) {
        validateEnvelope(frame, requestId);
        raiseIfError(frame);
        return frame;
      }
      throw new AgentControlError("agent control socket closed before responding", {
        code: "socket_closed",
        retryable: true,
      });
    } catch (err) {
      throw wrapSocketError(err);
    } finally {
      clearTimeout(deadline);
      socket.destroy();
    }
  }

  private connect(timeoutMs = this.requestTimeoutMs): Promise<Socket> {
    return new Promise<Socket>((resolve, reject) => {
      const socket = createConnection({ path: this.socketPath });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(
          new AgentControlError("timed out connecting to agent control socket", {
            code: "timeout",
            retryable: true,
          }),
        );
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(
          new AgentControlError(err.message, {
            code: "socket_io",
            retryable: true,
            cause: err,
          }),
        );
      });
    });
  }

  private writeEnvelope(socket: Socket, requestId: string, payload: Envelope): Promise<void> {
    const envelope: Envelope = {
      marmot_agent_control: AGENT_CONTROL_PROTOCOL_V1,
      id: requestId,
      ...payload,
    };
    if (this.authToken) {
      envelope.auth_token = this.authToken;
    }
    const frame = Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8");
    if (frame.length > MAX_AGENT_CONTROL_FRAME_BYTES) {
      return Promise.reject(
        new AgentControlError("agent control frame is too large", { code: "frame_too_large" }),
      );
    }
    return new Promise<void>((resolve, reject) => {
      socket.write(frame, (err) => {
        if (err) {
          reject(
            new AgentControlError(err.message, {
              code: "socket_io",
              retryable: true,
              cause: err,
            }),
          );
        } else {
          resolve();
        }
      });
    });
  }
}

function validateEnvelope(frame: Envelope, requestId: string): void {
  if (frame.marmot_agent_control !== AGENT_CONTROL_PROTOCOL_V1) {
    throw new AgentControlError(
      `wrong agent control protocol: ${String(frame.marmot_agent_control)}`,
      { code: "wrong_protocol" },
    );
  }
  if (frame.id !== requestId) {
    throw new AgentControlError("agent control response id mismatch", { code: "id_mismatch" });
  }
}

function raiseIfError(frame: Envelope): void {
  if (frame.type === "error") {
    throw new AgentControlError(String(frame.message ?? "agent control error"), {
      code: String(frame.code ?? "agent_control_error"),
    });
  }
}

function wrapSocketError(err: unknown): AgentControlError {
  if (err instanceof AgentControlError) {
    return err;
  }
  if (err instanceof Error) {
    return new AgentControlError(err.message, { code: "socket_io", retryable: true, cause: err });
  }
  return new AgentControlError("agent control socket error", { code: "socket_io", retryable: true });
}

/**
 * Yield decoded JSON frames (one per newline-delimited line) from a socket,
 * enforcing the 1 MiB frame cap so a peer that never sends a newline cannot make
 * us buffer unbounded.
 */
async function* readFrames(socket: Socket): AsyncGenerator<Envelope> {
  let buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  for await (const chunk of socket as AsyncIterable<Buffer>) {
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
    let newlineIndex = buffer.indexOf(0x0a);
    while (newlineIndex !== -1) {
      const line = buffer.subarray(0, newlineIndex);
      buffer = buffer.subarray(newlineIndex + 1);
      if (line.length > MAX_AGENT_CONTROL_FRAME_BYTES) {
        throw new AgentControlError("agent control frame is too large", { code: "frame_too_large" });
      }
      if (line.length > 0) {
        yield JSON.parse(line.toString("utf8")) as Envelope;
      }
      newlineIndex = buffer.indexOf(0x0a);
    }
    if (buffer.length > MAX_AGENT_CONTROL_FRAME_BYTES) {
      throw new AgentControlError("agent control frame is too large", { code: "frame_too_large" });
    }
  }
}
