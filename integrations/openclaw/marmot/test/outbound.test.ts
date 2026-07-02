import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import type {
  ChannelMessageSendMediaContext,
  ChannelMessageSendTextContext,
} from "openclaw/plugin-sdk/channel-outbound";

import type {
  AgentControlMediaUpload,
  MarmotAgentControlClient,
} from "../src/client.js";
import {
  createMarmotMessageAdapter,
  receiptFromMessageIds,
  SentMessageTargetCache,
} from "../src/outbound.js";

const HEX32 = (b: string) => b.repeat(32);

interface SendFinalCall {
  accountIdHex: string;
  groupIdHex: string;
  text: string;
  replyToMessageIdHex?: string | null;
}

interface SendMediaCall {
  accountIdHex: string;
  groupIdHex: string;
  attachments: AgentControlMediaUpload[];
  caption?: string | null;
}

interface DeleteCall {
  accountIdHex: string;
  groupIdHex: string;
  targetMessageIdHex: string;
}

interface ClientCalls {
  sendFinal: SendFinalCall[];
  sendMedia: SendMediaCall[];
  delete: DeleteCall[];
}

function emptyClientCalls(): ClientCalls {
  return { sendFinal: [], sendMedia: [], delete: [] };
}

/** Minimal stub of the control client capturing send_final / send_media / delete. */
function stubClient(calls: ClientCalls, messageIdsHex: string[] = [HEX32("ab")]): MarmotAgentControlClient {
  return {
    async sendFinal(
      accountIdHex: string,
      groupIdHex: string,
      text: string,
      replyToMessageIdHex?: string | null,
    ) {
      calls.sendFinal.push({ accountIdHex, groupIdHex, text, replyToMessageIdHex });
      return { type: "final_sent", message_ids_hex: messageIdsHex };
    },
    async sendMedia(
      accountIdHex: string,
      groupIdHex: string,
      attachments: AgentControlMediaUpload[],
      caption?: string | null,
    ) {
      calls.sendMedia.push({ accountIdHex, groupIdHex, attachments, caption });
      return { type: "final_sent", message_ids_hex: messageIdsHex };
    },
    async deleteMessage(accountIdHex: string, groupIdHex: string, targetMessageIdHex: string) {
      calls.delete.push({ accountIdHex, groupIdHex, targetMessageIdHex });
      return { type: "final_sent", message_ids_hex: [HEX32("de")] };
    },
  } as unknown as MarmotAgentControlClient;
}

describe("createMarmotMessageAdapter", () => {
  it("routes a durable text send to send_final and returns a receipt", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({
        client: stubClient(calls),
        marmotAccountIdHex: HEX32("aa"),
      }),
      nowMs: () => 1234,
    });

    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "done",
      replyToId: HEX32("dd"),
    } as unknown as ChannelMessageSendTextContext;

    const result = await adapter.send!.text!(ctx);

    expect(calls.sendFinal).toHaveLength(1);
    expect(calls.sendFinal[0]).toMatchObject({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      text: "done",
      replyToMessageIdHex: HEX32("dd"),
    });
    expect(result.receipt.primaryPlatformMessageId).toBe(HEX32("ab"));
    expect(result.receipt.platformMessageIds).toEqual([HEX32("ab")]);
    expect(result.receipt.parts[0]).toMatchObject({ kind: "text", index: 0 });
    expect(result.receipt.sentAt).toBe(1234);
  });

  it("declares durable text + media + replyTo capabilities (no unproven live caps)", () => {
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(emptyClientCalls()), marmotAccountIdHex: HEX32("aa") }),
    });
    expect(adapter.durableFinal?.capabilities).toEqual({ text: true, media: true, replyTo: true });
    expect(Object.prototype.hasOwnProperty.call(adapter, "live")).toBe(false);
  });

  it("routes a media send with a local path to send_media with the caption", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
      nowMs: () => 5678,
    });

    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "look at this",
      mediaUrl: "/tmp/openclaw/cat.png",
    } as unknown as ChannelMessageSendMediaContext;

    const result = await adapter.send!.media!(ctx);

    expect(calls.sendMedia).toHaveLength(1);
    expect(calls.sendMedia[0]).toMatchObject({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      caption: "look at this",
    });
    expect(calls.sendMedia[0]?.attachments[0]).toMatchObject({
      path: "/tmp/openclaw/cat.png",
      media_type: "image/png",
      file_name: "cat.png",
    });
    expect(result.receipt.parts[0]).toMatchObject({ kind: "media", index: 0 });
    expect(result.receipt.sentAt).toBe(5678);
  });

  it("resolves a file:// media url to a local path", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "",
      mediaUrl: "file:///tmp/openclaw/clip.mp4",
    } as unknown as ChannelMessageSendMediaContext;

    await adapter.send!.media!(ctx);

    expect(calls.sendMedia[0]?.attachments[0]).toMatchObject({
      path: "/tmp/openclaw/clip.mp4",
      media_type: "video/mp4",
      file_name: "clip.mp4",
    });
    // An empty caption is sent as null.
    expect(calls.sendMedia[0]?.caption).toBeNull();
  });

  it("materializes a remote media url with mediaReadFile into a temp file", async () => {
    const calls = emptyClientCalls();
    const writes: { fileName: string; bytes: Buffer }[] = [];
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
      writeTempMedia: async (fileName, bytes) => {
        writes.push({ fileName, bytes });
        return `/tmp/marmot-media/${fileName}`;
      },
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "remote",
      mediaUrl: "https://example.test/path/photo.jpg",
      mediaReadFile: async () => Buffer.from("fake-bytes"),
    } as unknown as ChannelMessageSendMediaContext;

    await adapter.send!.media!(ctx);

    expect(writes).toHaveLength(1);
    expect(writes[0]?.fileName).toBe("photo.jpg");
    expect(calls.sendMedia[0]?.attachments[0]).toMatchObject({
      path: "/tmp/marmot-media/photo.jpg",
      media_type: "image/jpeg",
      file_name: "photo.jpg",
    });
  });

  it("rejects a remote media url with no local-path accessor", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "remote",
      mediaUrl: "https://example.test/photo.jpg",
    } as unknown as ChannelMessageSendMediaContext;

    await expect(adapter.send!.media!(ctx)).rejects.toThrow(/local path/);
    expect(calls.sendMedia).toHaveLength(0);
  });

  it("rejects a local path outside the allowlist (no file read, no send)", async () => {
    // The exfiltration vector from the issue: a prompt-influenced mediaUrl
    // pointing at an arbitrary connector-host file (e.g. an ssh key). The guard
    // must reject it before the connector reads any bytes.
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "exfil",
      // Outside OpenClaw's default media roots; no explicit mediaLocalRoots.
      mediaUrl: "/home/victim/.ssh/id_rsa",
    } as unknown as ChannelMessageSendMediaContext;

    await expect(adapter.send!.media!(ctx)).rejects.toMatchObject({
      name: "LocalMediaAccessError",
    });
    expect(calls.sendMedia).toHaveLength(0);
  });

  it("rejects a file:// url that escapes the allowlist", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "exfil",
      mediaUrl: "file:///etc/passwd",
    } as unknown as ChannelMessageSendMediaContext;

    await expect(adapter.send!.media!(ctx)).rejects.toMatchObject({
      name: "LocalMediaAccessError",
    });
    expect(calls.sendMedia).toHaveLength(0);
  });

  it("rejects a local path outside an explicit ctx.mediaLocalRoots allowlist", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "exfil",
      mediaUrl: "/var/data/secret.png",
      // OpenClaw confines the send to this root; the path is outside it.
      mediaLocalRoots: ["/srv/openclaw/media"],
    } as unknown as ChannelMessageSendMediaContext;

    await expect(adapter.send!.media!(ctx)).rejects.toMatchObject({
      name: "LocalMediaAccessError",
    });
    expect(calls.sendMedia).toHaveLength(0);
  });

  it("allows a local path under an explicit ctx.mediaLocalRoots allowlist", async () => {
    // OpenClaw can hand the channel a non-default approved root; a path under it
    // must be accepted (the guard honors the send's own allowlist, not only the
    // SDK defaults).
    const tmpRoot = await mkdtemp(join(tmpdir(), "marmot-outbound-test-"));
    try {
      const filePath = join(tmpRoot, "photo.png");
      await writeFile(filePath, Buffer.from("png-bytes"));
      const calls = emptyClientCalls();
      const adapter = createMarmotMessageAdapter({
        resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
      });
      const ctx = {
        cfg: {},
        to: HEX32("cc"),
        text: "look",
        mediaUrl: filePath,
        mediaLocalRoots: [tmpRoot],
      } as unknown as ChannelMessageSendMediaContext;

      await adapter.send!.media!(ctx);

      expect(calls.sendMedia).toHaveLength(1);
      expect(calls.sendMedia[0]?.attachments[0]).toMatchObject({
        path: filePath,
        media_type: "image/png",
        file_name: "photo.png",
      });
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("honors ctx.mediaAccess.localRoots when mediaLocalRoots is absent", async () => {
    const tmpRoot = await mkdtemp(join(tmpdir(), "marmot-outbound-test-"));
    try {
      const filePath = join(tmpRoot, "clip.mp4");
      await writeFile(filePath, Buffer.from("mp4-bytes"));
      const calls = emptyClientCalls();
      const adapter = createMarmotMessageAdapter({
        resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
      });
      const ctx = {
        cfg: {},
        to: HEX32("cc"),
        text: "clip",
        mediaUrl: filePath,
        mediaAccess: { localRoots: [tmpRoot] },
      } as unknown as ChannelMessageSendMediaContext;

      await adapter.send!.media!(ctx);

      expect(calls.sendMedia).toHaveLength(1);
      expect(calls.sendMedia[0]?.attachments[0]?.path).toBe(filePath);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("records sent ids in the cache and a delete resolves the group from it", async () => {
    const calls = emptyClientCalls();
    const sentId = HEX32("99");
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls, [sentId]), marmotAccountIdHex: HEX32("aa") }),
    });

    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "deletable",
    } as unknown as ChannelMessageSendTextContext;
    await adapter.send!.text!(ctx);

    expect(adapter.sentTargets.get(sentId)).toEqual({
      marmotAccountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
    });

    const deleted = await adapter.deleteByMessageId(sentId, { cfg: {}, accountId: null });
    expect(deleted).toBe(true);
    expect(calls.delete).toEqual([
      { accountIdHex: HEX32("aa"), groupIdHex: HEX32("cc"), targetMessageIdHex: sentId },
    ]);
  });

  it("deleteByMessageId routes the cache-hit delete with the action's account context", async () => {
    const calls = emptyClientCalls();
    const sentId = HEX32("99");
    const resolveCalls: { cfg: unknown; accountId?: string | null }[] = [];
    const adapter = createMarmotMessageAdapter({
      resolveTarget: (cfg, accountId) => {
        resolveCalls.push({ cfg, accountId });
        return { client: stubClient(calls, [sentId]), marmotAccountIdHex: HEX32("aa") };
      },
    });
    // Seed the send-time cache directly via its typed API (no ctx construction).
    adapter.sentTargets.record(sentId, {
      marmotAccountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
    });

    const deleted = await adapter.deleteByMessageId(sentId, {
      cfg: { marker: "delete-cfg" },
      accountId: "acct-2",
    });
    expect(deleted).toBe(true);
    // The delete resolve must use the action's own cfg + accountId, not a
    // context-free resolve (which would mis-route in a multi-account deployment).
    expect(resolveCalls.at(-1)).toEqual({ cfg: { marker: "delete-cfg" }, accountId: "acct-2" });
  });

  it("deleteByMessageId returns false for an unknown (uncached) message id", async () => {
    const calls = emptyClientCalls();
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient(calls), marmotAccountIdHex: HEX32("aa") }),
    });
    expect(await adapter.deleteByMessageId(HEX32("77"), { cfg: {}, accountId: null })).toBe(false);
    expect(calls.delete).toHaveLength(0);
  });
});

describe("SentMessageTargetCache", () => {
  it("evicts the oldest entry past the bound", () => {
    const cache = new SentMessageTargetCache(2);
    cache.record(HEX32("01"), { marmotAccountIdHex: HEX32("aa"), groupIdHex: HEX32("c1") });
    cache.record(HEX32("02"), { marmotAccountIdHex: HEX32("aa"), groupIdHex: HEX32("c2") });
    cache.record(HEX32("03"), { marmotAccountIdHex: HEX32("aa"), groupIdHex: HEX32("c3") });
    expect(cache.get(HEX32("01"))).toBeUndefined();
    expect(cache.get(HEX32("02"))?.groupIdHex).toBe(HEX32("c2"));
    expect(cache.get(HEX32("03"))?.groupIdHex).toBe(HEX32("c3"));
    expect(cache.size).toBe(2);
  });
});

describe("receiptFromMessageIds", () => {
  it("throws when dm-agent returns no message ids", () => {
    expect(() => receiptFromMessageIds([], 0)).toThrow();
  });

  it("builds parts for each durable message id", () => {
    const receipt = receiptFromMessageIds([HEX32("ab"), HEX32("ac")], 7);
    expect(receipt.platformMessageIds).toEqual([HEX32("ab"), HEX32("ac")]);
    expect(receipt.parts.map((p) => p.index)).toEqual([0, 1]);
    expect(receipt.sentAt).toBe(7);
  });
});
