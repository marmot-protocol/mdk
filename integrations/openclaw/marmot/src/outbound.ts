// Outbound message adapter (durable kind-9 sends) for the OpenClaw channel.
//
// Built with the current `openclaw/plugin-sdk/channel-outbound` message
// lifecycle: `send.text` is the durable final path and maps onto dm-agent's
// `send_final`; `send.media` maps onto dm-agent's `send_media`. Live QUIC
// previews are layered on separately via the finalizable-live-preview adapter
// (see src/live.ts) and are only declared as capabilities once backed by
// contract tests.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  defineChannelMessageAdapter,
  type ChannelMessageSendMediaContext,
  type ChannelMessageSendTextContext,
  type MessageReceipt,
  type MessageReceiptPart,
} from "openclaw/plugin-sdk/channel-outbound";
import {
  assertLocalMediaAllowed,
  getDefaultLocalRoots,
} from "openclaw/plugin-sdk/media-runtime";

import type { AgentControlMediaUpload, MarmotAgentControlClient } from "./client.js";

/** Marmot send target resolved from OpenClaw config + the inbound chat id. */
export interface ResolvedMarmotTarget {
  client: MarmotAgentControlClient;
  marmotAccountIdHex: string;
}

export interface MarmotMessageAdapterDeps {
  /**
   * Resolve the dm-agent client and the Marmot agent account for an outbound
   * send. `accountId` is OpenClaw's per-account id; `cfg` is the gateway config.
   */
  resolveTarget: (
    cfg: unknown,
    accountId?: string | null,
  ) => ResolvedMarmotTarget | Promise<ResolvedMarmotTarget>;
  nowMs?: () => number;
  /** Override the temp-file writer used to materialize a buffer-only media source (tests). */
  writeTempMedia?: (fileName: string, bytes: Buffer) => Promise<string>;
}

/** Build an OpenClaw `MessageReceipt` from dm-agent's durable message ids. */
export function receiptFromMessageIds(
  messageIdsHex: string[],
  nowMs: number,
  kind: MessageReceiptPart["kind"] = "text",
): MessageReceipt {
  if (messageIdsHex.length === 0) {
    throw new Error("dm-agent send returned no durable message ids");
  }
  const parts: MessageReceiptPart[] = messageIdsHex.map((id, index) => ({
    platformMessageId: id,
    kind,
    index,
  }));
  return {
    primaryPlatformMessageId: messageIdsHex[0],
    platformMessageIds: messageIdsHex,
    parts,
    sentAt: nowMs,
  };
}

// --- send-time message -> conversation cache (Seam 4 groundwork) -------------

/** Where a durable message was sent, recorded so a later delete can be routed. */
export interface SentMessageTarget {
  marmotAccountIdHex: string;
  groupIdHex: string;
}

/**
 * Bounded, insertion-ordered map from a durable message id to the
 * account+group it was sent to. An agent-invoked delete receipt carries no
 * conversation id (see Seam 4 report in README/AGENTS), so the only way to
 * route `delete_message` is to remember where each id was sent. Bounded so a
 * long-lived adapter never grows without limit.
 */
export class SentMessageTargetCache {
  private readonly entries = new Map<string, SentMessageTarget>();

  constructor(private readonly max = 2048) {}

  record(messageIdHex: string, target: SentMessageTarget): void {
    if (this.entries.has(messageIdHex)) {
      this.entries.delete(messageIdHex);
    }
    this.entries.set(messageIdHex, target);
    if (this.entries.size > this.max) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) {
        this.entries.delete(oldest);
      }
    }
  }

  recordAll(messageIdsHex: readonly string[], target: SentMessageTarget): void {
    for (const id of messageIdsHex) {
      this.record(id, target);
    }
  }

  get(messageIdHex: string): SentMessageTarget | undefined {
    return this.entries.get(messageIdHex);
  }

  get size(): number {
    return this.entries.size;
  }
}

// --- outbound media resolution (Seam 2) -------------------------------------

/** Map a file extension onto a best-effort MIME type; dm-agent re-detects from bytes. */
function mimeFromExtension(fileName: string): string {
  const ext = extname(fileName).toLowerCase();
  switch (ext) {
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".gif":
      return "image/gif";
    case ".webp":
      return "image/webp";
    case ".heic":
      return "image/heic";
    case ".mp4":
      return "video/mp4";
    case ".mov":
      return "video/quicktime";
    case ".webm":
      return "video/webm";
    case ".mp3":
      return "audio/mpeg";
    case ".m4a":
      return "audio/mp4";
    case ".ogg":
      return "audio/ogg";
    case ".wav":
      return "audio/wav";
    case ".pdf":
      return "application/pdf";
    default:
      return "application/octet-stream";
  }
}

/** True for `mediaUrl` values that are already a local filesystem reference. */
function isLocalMediaUrl(mediaUrl: string): boolean {
  if (mediaUrl.startsWith("file://")) {
    return true;
  }
  // Absolute or relative filesystem path (not a network scheme).
  return !/^[a-z][a-z0-9+.-]*:\/\//i.test(mediaUrl);
}

/**
 * A resolved outbound media upload, plus an optional cleanup for any temp file
 * staged on the connector host. The cleanup is present only for the remote-URL
 * case (a temp file we created); an already-local path is left untouched.
 */
export interface ResolvedOutboundMediaUpload {
  upload: AgentControlMediaUpload;
  cleanup?: () => Promise<void>;
}

/**
 * Resolve the allowlist of local roots an outbound local-path send is confined
 * to. OpenClaw hands the channel the approved roots on the send ctx
 * (`mediaLocalRoots`, or `mediaAccess.localRoots`); when neither is present we
 * fall back to OpenClaw's default media-store roots. We never honor a `"any"`
 * sentinel here: the connector reads the resolved path verbatim, so an
 * unrestricted root would reintroduce the arbitrary-file-read this guard exists
 * to close. An empty configured allowlist means "nothing is allowed".
 */
function resolveAllowedMediaRoots(ctx: ChannelMessageSendMediaContext): readonly string[] {
  const configured = ctx.mediaLocalRoots ?? ctx.mediaAccess?.localRoots;
  return configured ?? getDefaultLocalRoots();
}

/**
 * Resolve `ctx.mediaUrl` to a local `AgentControlMediaUpload` the connector can
 * read by path. Handles two cases the ctx can express with the real SDK types:
 *
 * 1. A local filesystem path or `file://` URL — validated against the send's
 *    allowlisted media roots (`assertLocalMediaAllowed`) and then used directly
 *    (no cleanup). The connector reads this path verbatim, so without the guard
 *    an agent-influenced `mediaUrl` (e.g. `~/.ssh/id_rsa`) would let a prompt-
 *    injected agent exfiltrate any connector-host file into a group. This
 *    mirrors the inbound trust model, where downloaded media is re-staged under
 *    an allowlisted root before the agent's image tool can read it.
 * 2. A non-local URL with a `mediaReadFile` host accessor — the bytes are read
 *    through that already-authorized host reader and written to a temp file so
 *    the connector still gets a path, and a `cleanup` is returned to remove that
 *    temp file+dir after the send. No path allowlist applies because the path is
 *    one we just minted under our own temp dir, not a caller-supplied path.
 *
 * Returns `null` when the ctx provides only a remote URL and no buffer accessor;
 * the connector reads a path it cannot be given in that case (see Seam 2 note).
 *
 * Throws `LocalMediaAccessError` (from the SDK) when a local path escapes the
 * allowlist; the caller surfaces that as a failed send rather than reading the
 * file.
 */
async function resolveOutboundMediaUpload(
  ctx: ChannelMessageSendMediaContext,
  writeTempMedia: (fileName: string, bytes: Buffer) => Promise<string>,
): Promise<ResolvedOutboundMediaUpload | null> {
  const { mediaUrl } = ctx;
  if (isLocalMediaUrl(mediaUrl)) {
    const localPath = mediaUrl.startsWith("file://") ? fileURLToPath(mediaUrl) : mediaUrl;
    // Defense against exfiltration via a tool/prompt-influenced path: the
    // connector reads this path unconditionally, so confine it to the send's
    // allowlisted media roots before handing it over. Throws on violation.
    await assertLocalMediaAllowed(localPath, resolveAllowedMediaRoots(ctx));
    const fileName = basename(localPath) || "attachment";
    return {
      upload: { path: localPath, media_type: mimeFromExtension(fileName), file_name: fileName },
    };
  }
  const readFile = ctx.mediaReadFile;
  if (readFile) {
    const bytes = await readFile(mediaUrl);
    const fileName = basename(new URL(mediaUrl).pathname) || "attachment";
    const path = await writeTempMedia(fileName, bytes);
    return {
      upload: { path, media_type: mimeFromExtension(fileName), file_name: fileName },
      // The staged temp file lives under a dedicated mkdtemp dir; remove the
      // whole dir so nothing is left behind after the send.
      cleanup: () => rm(dirname(path), { recursive: true, force: true }),
    };
  }
  return null;
}

/** Default temp-file writer: materialize media bytes under a fresh temp dir (0600). */
async function defaultWriteTempMedia(fileName: string, bytes: Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "marmot-media-"));
  const path = join(dir, fileName || "attachment");
  await writeFile(path, bytes, { mode: 0o600 });
  return path;
}

/**
 * Define the Marmot channel message adapter. The durable text send routes to
 * dm-agent `send_final`; the media send routes to `send_media`. The chat id
 * (`ctx.to`) is the Marmot group id hex and `ctx.replyToId` is a durable
 * message id hex. Every durable send records its returned ids in
 * {@link SentMessageTargetCache} so a later delete can be routed.
 */
export function createMarmotMessageAdapter(deps: MarmotMessageAdapterDeps) {
  const now = deps.nowMs ?? (() => Date.now());
  const writeTempMedia = deps.writeTempMedia ?? defaultWriteTempMedia;
  // Lives in the adapter closure: maps each durable message id we return back to
  // the account+group it was sent to, so an agent delete can be routed by id.
  const sentTargets = new SentMessageTargetCache();

  /**
   * Resolve a previously-sent message id to its account+group. Used by a delete
   * trigger once the SDK exposes a typed adapter delete hook (see Seam 4 note);
   * exposed here so the cache + lookup is ready to wire.
   *
   * `resolveCtx` carries the delete action's own routing context (`cfg` +
   * `accountId`) so the dm-agent client is resolved for the correct account in a
   * multi-account deployment, rather than defaulting to whatever account a
   * context-free resolve would pick.
   */
  const deleteByMessageId = async (
    targetMessageIdHex: string,
    resolveCtx: { cfg: unknown; accountId?: string | null },
  ): Promise<boolean> => {
    const target = sentTargets.get(targetMessageIdHex);
    if (!target) {
      return false;
    }
    const { client } = await deps.resolveTarget(resolveCtx.cfg, resolveCtx.accountId ?? null);
    await client.deleteMessage(target.marmotAccountIdHex, target.groupIdHex, targetMessageIdHex);
    return true;
  };

  const adapter = defineChannelMessageAdapter({
    id: "marmot",
    durableFinal: {
      // Marmot durable sends are plain encrypted kind-9 text or media with an
      // optional reply.
      capabilities: { text: true, media: true, replyTo: true },
    },
    send: {
      text: async (ctx: ChannelMessageSendTextContext) => {
        const { client, marmotAccountIdHex } = await deps.resolveTarget(ctx.cfg, ctx.accountId);
        const response = await client.sendFinal(
          marmotAccountIdHex,
          ctx.to,
          ctx.text,
          ctx.replyToId ?? null,
        );
        sentTargets.recordAll(response.message_ids_hex, {
          marmotAccountIdHex,
          groupIdHex: ctx.to,
        });
        return { receipt: receiptFromMessageIds(response.message_ids_hex, now()) };
      },
      media: async (ctx: ChannelMessageSendMediaContext) => {
        const resolved = await resolveOutboundMediaUpload(ctx, writeTempMedia);
        if (!resolved) {
          throw new Error(
            "marmot: outbound media has no local path; dm-agent send_media needs a file path",
          );
        }
        try {
          const { client, marmotAccountIdHex } = await deps.resolveTarget(ctx.cfg, ctx.accountId);
          const caption = ctx.text.trim().length > 0 ? ctx.text : null;
          const response = await client.sendMedia(
            marmotAccountIdHex,
            ctx.to,
            [resolved.upload],
            caption,
          );
          sentTargets.recordAll(response.message_ids_hex, {
            marmotAccountIdHex,
            groupIdHex: ctx.to,
          });
          return { receipt: receiptFromMessageIds(response.message_ids_hex, now(), "media") };
        } finally {
          // Remove any temp file we staged for a remote URL, even if the send
          // threw. The already-local case has no cleanup.
          await resolved.cleanup?.().catch(() => undefined);
        }
      },
    },
    receive: {
      defaultAckPolicy: "after_agent_dispatch",
      supportedAckPolicies: ["after_agent_dispatch", "manual"],
    },
  });

  // Expose the cache + delete helper for the delete trigger and for tests
  // without widening the SDK adapter shape.
  return Object.assign(adapter, { sentTargets, deleteByMessageId });
}
