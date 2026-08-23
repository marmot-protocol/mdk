// Outbound message adapter (durable kind-9 sends) for the OpenClaw channel.
//
// Built with the current `openclaw/plugin-sdk/channel-outbound` message
// lifecycle: `send.text` is the durable final path and maps onto wn-agent's
// `send_final`; `send.media` maps onto wn-agent's `send_media`. Live QUIC
// previews are layered on separately via the finalizable-live-preview adapter
// (see src/live.ts) and are only declared as capabilities once backed by
// contract tests.

import { randomUUID } from "node:crypto";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  defineChannelMessageAdapter,
  type ChannelMessageSendMediaContext,
  type ChannelMessageSendTextContext,
  type MessageReceipt,
  type MessageReceiptPart,
} from "openclaw/plugin-sdk/channel-outbound";
// `readLocalFileFromRoots` (allowlist check + hardened read) and the local media
// access types are imported from the subpaths that export them on both the
// `latest` and `beta` OpenClaw channels. The `plugin-sdk/media-runtime` barrel
// dropped `assertLocalMediaAllowed`/`getDefaultLocalRoots` in 2026.7.2-beta.
import { readLocalFileFromRoots } from "openclaw/plugin-sdk/infra-runtime";
import { extractOriginalFilename, getMediaDir } from "openclaw/plugin-sdk/media-runtime";
import { getDefaultLocalRoots, LocalMediaAccessError } from "openclaw/plugin-sdk/web-media";

import type { AgentControlMediaUpload, MarmotAgentControlClient } from "./client.js";
import { markMarmotOutboundSent } from "./runtime-state.js";

/** Marmot send target resolved from OpenClaw config + the inbound chat id. */
export interface ResolvedMarmotTarget {
  client: MarmotAgentControlClient;
  marmotAccountIdHex: string;
}

export interface MarmotMessageAdapterDeps {
  /**
   * Resolve the wn-agent client and the Marmot agent account for an outbound
   * send. `accountId` is OpenClaw's per-account id; `cfg` is the gateway config.
   */
  resolveTarget: (
    cfg: unknown,
    accountId?: string | null,
  ) => ResolvedMarmotTarget | Promise<ResolvedMarmotTarget>;
  nowMs?: () => number;
  /** Override the temp-file writer used to materialize a buffer-only media source (tests). */
  writeTempMedia?: (fileName: string, bytes: Buffer) => Promise<string>;
  /** Override the connector-shared outbound staging directory (tests/deployments). */
  outboundMediaDir?: string;
  /** Override the staged-file permission adjustment (tests). */
  chmodTempMedia?: (path: string, mode: number) => Promise<void>;
}

/** Build an OpenClaw `MessageReceipt` from wn-agent's durable message ids. */
export function receiptFromMessageIds(
  messageIdsHex: string[],
  nowMs: number,
  kind: MessageReceiptPart["kind"] = "text",
): MessageReceipt {
  if (messageIdsHex.length === 0) {
    throw new Error("wn-agent send returned no durable message ids");
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

/** Map a file extension onto a best-effort MIME type; wn-agent re-detects from bytes. */
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

/** Restore a caller-facing name when OpenClaw has staged a buffer in its media store. */
function localMediaFileName(localPath: string): string {
  const storedName = basename(localPath) || "attachment";
  const mediaRelativePath = relative(resolve(getMediaDir()), resolve(localPath));
  const isManagedMedia =
    mediaRelativePath === "" ||
    (mediaRelativePath !== ".." &&
      !mediaRelativePath.startsWith(`..${sep}`) &&
      !isAbsolute(mediaRelativePath));
  return isManagedMedia ? extractOriginalFilename(storedName) : storedName;
}

/**
 * A resolved outbound media upload plus cleanup for the private copy staged in
 * the connector-shared outbound directory.
 */
export interface ResolvedOutboundMediaUpload {
  upload: AgentControlMediaUpload;
  cleanup?: () => Promise<void>;
}

/**
 * Resolve the fallback allowlist used when an outbound local-path send has no
 * host-provided reader. OpenClaw hands the channel the approved roots on the
 * send ctx (`mediaLocalRoots`, or `mediaAccess.localRoots`); when neither is
 * present we fall back to OpenClaw's default media-store roots. We never honor
 * a `"any"` sentinel here: the gateway reads and stages the source, so an
 * unrestricted source root would reintroduce the arbitrary-file-read this guard
 * exists to close. An empty configured allowlist means "nothing is allowed".
 */
function resolveAllowedMediaRoots(ctx: ChannelMessageSendMediaContext): readonly string[] {
  const configured = ctx.mediaLocalRoots ?? ctx.mediaAccess?.localRoots;
  return configured ?? getDefaultLocalRoots();
}

/**
 * Resolve `ctx.mediaUrl` to a local `AgentControlMediaUpload` the connector can
 * read by path. Handles two cases the ctx can express with the real SDK types:
 *
 * 1. Any source with a host-provided `mediaReadFile` accessor — read through
 *    that already-authorized host capability and copied to the connector-
 *    shared staging root. This includes local paths: the running host owns the
 *    active agent's media policy, which may differ from this connector's pinned
 *    SDK defaults.
 * 2. A local filesystem path or `file://` URL with no host accessor — read only
 *    through the send's allowlisted media roots (`readLocalFileFromRoots`), then
 *    copied to the connector-shared staging root. Without the source guard
 *    an agent-influenced `mediaUrl` (e.g. `~/.ssh/id_rsa`) would let a prompt-
 *    injected agent exfiltrate any connector-host file into a group. This
 *    mirrors the inbound trust model, where downloaded media is re-staged under
 *    an allowlisted root before the agent's image tool can read it.
 *
 * Returns `null` when the ctx provides only a remote URL and no buffer accessor;
 * the connector reads a path it cannot be given in that case (see Seam 2 note).
 *
 * When the host reader is absent, throws `LocalMediaAccessError` (from the SDK)
 * if a local path cannot be read from the allowlisted roots; the caller surfaces
 * that as a failed send. A path outside the roots is never opened — the allowlist
 * check and the read are the same operation — but the error does not distinguish
 * that from an in-root read failure, so treat it as "refused", not specifically
 * "escaped the allowlist". Errors from a host reader propagate unchanged.
 */
async function resolveOutboundMediaUpload(
  ctx: ChannelMessageSendMediaContext,
  writeTempMedia: (fileName: string, bytes: Buffer) => Promise<string>,
): Promise<ResolvedOutboundMediaUpload | null> {
  const { mediaUrl } = ctx;
  const local = isLocalMediaUrl(mediaUrl);
  const localPath = local
    ? mediaUrl.startsWith("file://")
      ? fileURLToPath(mediaUrl)
      : mediaUrl
    : undefined;
  const mediaReadFile = ctx.mediaReadFile ?? ctx.mediaAccess?.readFile;
  if (mediaReadFile) {
    const bytes = await mediaReadFile(mediaUrl);
    const fileName = localPath
      ? localMediaFileName(localPath)
      : basename(new URL(mediaUrl).pathname) || "attachment";
    const path = await writeTempMedia(fileName, bytes);
    return {
      upload: { path, media_type: mimeFromExtension(fileName), file_name: fileName },
      cleanup: () => rm(path, { force: true }),
    };
  }
  if (localPath) {
    // Defense against exfiltration via a tool/prompt-influenced path: the read
    // itself is confined to the allowlisted roots, so a path outside them is
    // never opened. Keep OpenClaw's source policy as the first layer; wn-agent
    // independently confines the staged path it ultimately reads.
    const read = await readLocalFileFromRoots({
      filePath: localPath,
      roots: resolveAllowedMediaRoots(ctx),
      label: "outbound media roots",
    });
    // `readLocalFileFromRoots` collapses every failure to `null`: an allowlist
    // miss, but also a missing file, an IO error, or a symlink/hardlink policy
    // rejection *under* an allowed root. Fail closed on all of them, but do not
    // claim which one it was — a missing in-root attachment should not read as
    // an exfiltration attempt in the logs.
    if (!read) {
      throw new LocalMediaAccessError(
        "path-not-allowed",
        "marmot: outbound media is not readable from the allowed local media roots",
      );
    }
    const fileName = localMediaFileName(localPath);
    const path = await writeTempMedia(fileName, read.buffer);
    return {
      upload: { path, media_type: mimeFromExtension(fileName), file_name: fileName },
      cleanup: () => rm(path, { force: true }),
    };
  }
  return null;
}

function defaultOutboundMediaDir(): string {
  if (process.env.MARMOT_OUTBOUND_MEDIA_DIR) {
    return process.env.MARMOT_OUTBOUND_MEDIA_DIR;
  }
  return join(process.env.MARMOT_HOME ?? join(homedir(), ".marmot"), "dev", "outbound-media");
}

/** Stage bytes under the connector-approved root; each copy is group-readable for split-user deployments. */
async function defaultWriteTempMedia(
  fileName: string,
  bytes: Buffer,
  outboundMediaDir = defaultOutboundMediaDir(),
  chmodTempMedia: (path: string, mode: number) => Promise<void> = chmod,
): Promise<string> {
  await mkdir(outboundMediaDir, { recursive: true, mode: 0o700 });
  const safeName = basename(fileName || "attachment") || "attachment";
  const path = join(outboundMediaDir, `${randomUUID()}-${safeName}`);
  await writeFile(path, bytes, { flag: "wx", mode: 0o640 });
  try {
    await chmodTempMedia(path, 0o640);
  } catch (error) {
    // Do not strand plaintext if the split-user permission adjustment fails
    // before resolution can return its normal cleanup callback.
    await rm(path, { force: true }).catch(() => undefined);
    throw error;
  }
  return path;
}

/**
 * Define the Marmot channel message adapter. The durable text send routes to
 * wn-agent `send_final`; the media send routes to `send_media`. The chat id
 * (`ctx.to`) is the Marmot group id hex and `ctx.replyToId` is a durable
 * message id hex. Every durable send records its returned ids in
 * {@link SentMessageTargetCache} so a later delete can be routed.
 */
export function createMarmotMessageAdapter(deps: MarmotMessageAdapterDeps) {
  const now = deps.nowMs ?? (() => Date.now());
  const writeTempMedia =
    deps.writeTempMedia ??
    ((fileName: string, bytes: Buffer) =>
      defaultWriteTempMedia(fileName, bytes, deps.outboundMediaDir, deps.chmodTempMedia));
  // Lives in the adapter closure: maps each durable message id we return back to
  // the account+group it was sent to, so an agent delete can be routed by id.
  const sentTargets = new SentMessageTargetCache();

  /**
   * Resolve a previously-sent message id to its account+group. Used by a delete
   * trigger once the SDK exposes a typed adapter delete hook (see Seam 4 note);
   * exposed here so the cache + lookup is ready to wire.
   *
   * `resolveCtx` carries the delete action's own routing context (`cfg` +
   * `accountId`) so the wn-agent client is resolved for the correct account in a
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
      capabilities: {
        text: true,
        media: true,
        replyTo: true,
        messageSendingHooks: true,
      },
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
        const receipt = receiptFromMessageIds(response.message_ids_hex, now());
        markMarmotOutboundSent(ctx.accountId, receipt.sentAt);
        return { receipt };
      },
      media: async (ctx: ChannelMessageSendMediaContext) => {
        const resolved = await resolveOutboundMediaUpload(ctx, writeTempMedia);
        if (!resolved) {
          throw new Error(
            "marmot: outbound media has no local path; wn-agent send_media needs a file path",
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
          const receipt = receiptFromMessageIds(response.message_ids_hex, now(), "media");
          markMarmotOutboundSent(ctx.accountId, receipt.sentAt);
          return { receipt };
        } finally {
          // Remove the staged copy even if the connector send threw. The
          // original source remains untouched.
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
