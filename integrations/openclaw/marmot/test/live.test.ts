import { describe, expect, it } from "vitest";

import { NonAppendOnlyUpdateError } from "../src/append-only.js";
import { MarmotLivePreview, type StreamControlClient } from "../src/live.js";
import { AgentTextStreamTranscript } from "../src/transcript.js";

const HEX32 = (b: string) => b.repeat(32);
const STREAM_ID = HEX32("11");
const START_ID = HEX32("22");

// Rust-anchored expectations from test/vectors/transcript-vectors.json with
// stream_id=0x11*32, start=0x22*32, chunk_bytes=1024.
const SINGLE_TEXT_HASH = "7484dc0c66dd50ac2fb0dbb11e59d65e9d967eee2c4b73b01e172ed4c5bd218a";
const INCREMENTAL_HASH = "412b9bd20aedf322174fab2b1dee909992044fa166391027f4b8fb730d5c5a81";

interface Calls {
  begin: { account: string; group: string; quic: string[] }[];
  append: { streamId: string; text: string }[];
  status: { streamId: string; text: string }[];
  progress: { streamId: string; text: string }[];
  finalize: { streamId: string; finalText: string; hash: string; count: number }[];
  cancel: { streamId: string; reason: string | null }[];
}

function emptyCalls(): Calls {
  return { begin: [], append: [], status: [], progress: [], finalize: [], cancel: [] };
}

function stubStreamClient(calls: Calls): StreamControlClient {
  return {
    async streamBegin(account: string, group: string, opts?: { quicCandidates?: Iterable<string> }) {
      const quic = [...(opts?.quicCandidates ?? [])];
      calls.begin.push({ account, group, quic });
      return {
        type: "stream_begun",
        stream_id_hex: STREAM_ID,
        start_message_id_hex: START_ID,
        quic_candidates: quic,
      };
    },
    async streamAppend(streamId: string, text: string) {
      calls.append.push({ streamId, text });
      return { type: "ack" };
    },
    async streamStatus(streamId: string, text: string) {
      calls.status.push({ streamId, text });
      return { type: "ack" };
    },
    async streamProgress(streamId: string, text: string) {
      calls.progress.push({ streamId, text });
      return { type: "ack" };
    },
    async streamFinalize(streamId: string, finalText: string, hash: string, count: number) {
      calls.finalize.push({ streamId, finalText, hash, count });
      return { type: "stream_finalized", stream_id_hex: streamId, message_ids_hex: [HEX32("ab")] };
    },
    async streamCancel(streamId: string, reason?: string | null) {
      calls.cancel.push({ streamId, reason: reason ?? null });
      return { type: "ack" };
    },
  } as unknown as StreamControlClient;
}

function preview(calls: Calls): MarmotLivePreview {
  return previewWithClient(stubStreamClient(calls));
}

function previewWithClient(client: StreamControlClient): MarmotLivePreview {
  return new MarmotLivePreview(client, {
    accountIdHex: HEX32("aa"),
    groupIdHex: HEX32("cc"),
    quicCandidates: ["quic://broker:4450"],
  });
}

function gatedBeginClient(calls: Calls): {
  client: StreamControlClient;
  releaseBegin: () => void;
  beginCount: () => number;
} {
  let releaseBegin: () => void = () => undefined;
  const beginGate = new Promise<void>((resolve) => {
    releaseBegin = resolve;
  });
  let beginCount = 0;
  const client = {
    ...stubStreamClient(calls),
    async streamBegin(account: string, group: string, opts?: { quicCandidates?: Iterable<string> }) {
      beginCount += 1;
      await beginGate;
      const quic = [...(opts?.quicCandidates ?? [])];
      calls.begin.push({ account, group, quic });
      return {
        type: "stream_begun",
        stream_id_hex: STREAM_ID,
        start_message_id_hex: START_ID,
        quic_candidates: quic,
      };
    },
  } as unknown as StreamControlClient;

  return { client, releaseBegin, beginCount: () => beginCount };
}

describe("MarmotLivePreview", () => {
  it("begins lazily and finalizes with the Rust transcript hash for one chunk", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.update("hello world");
    expect(live.isActive).toBe(true);
    const result = await live.finalize("hello world");
    expect(live.isActive).toBe(false);

    expect(calls.begin).toHaveLength(1);
    expect(calls.begin[0]?.quic).toEqual(["quic://broker:4450"]);
    expect(calls.append.map((a) => a.text)).toEqual(["hello world"]);
    expect(calls.finalize[0]).toMatchObject({
      streamId: STREAM_ID,
      finalText: "hello world",
      hash: SINGLE_TEXT_HASH,
      count: 1,
    });
    expect(result.messageIdsHex).toEqual([HEX32("ab")]);
  });

  it("reduces incremental updates to append-only deltas matching the Rust hash", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.update("hel");
    await live.update("hello");
    await live.update("hello world");
    await live.finalize("hello world");

    expect(calls.append.map((a) => a.text)).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toMatchObject({ hash: INCREMENTAL_HASH, count: 3 });
  });

  it("appends explicit deltas without requiring a full snapshot", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.appendDelta("hel");
    await live.appendDelta("lo");
    await live.appendDelta(" world");
    expect(live.currentText).toBe("hello world");
    await live.finalize("hello world");

    expect(calls.append.map((a) => a.text)).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toMatchObject({ hash: INCREMENTAL_HASH, count: 3 });
  });

  it("can begin before text arrives without adding transcript records", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.begin();
    await live.update("hello world");
    await live.finalize("hello world");

    expect(calls.begin).toHaveLength(1);
    expect(calls.append.map((a) => a.text)).toEqual(["hello world"]);
    expect(calls.status).toEqual([]);
    expect(calls.progress).toEqual([]);
    expect(calls.finalize[0]).toMatchObject({ hash: SINGLE_TEXT_HASH, count: 1 });
  });

  it("streams the whole final when finalize is called without prior updates", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.finalize("hello world");
    expect(calls.append.map((a) => a.text)).toEqual(["hello world"]);
    expect(calls.finalize[0]).toMatchObject({ hash: SINGLE_TEXT_HASH, count: 1 });
  });

  it("includes progress/status records in the transcript without changing final text", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.status("thinking");
    await live.progress("searching");
    await live.finalize("done");

    const transcript = new AgentTextStreamTranscript(
      Buffer.from(STREAM_ID, "hex"),
      Buffer.from(START_ID, "hex"),
    );
    transcript.appendStatus("thinking");
    transcript.appendProgress("searching");
    transcript.appendText("done");

    expect(calls.status.map((c) => c.text)).toEqual(["thinking"]);
    expect(calls.progress.map((c) => c.text)).toEqual(["searching"]);
    expect(calls.append.map((a) => a.text)).toEqual(["done"]);
    expect(calls.finalize[0]).toMatchObject({
      finalText: "done",
      hash: transcript.hashHex,
      count: transcript.chunkCount,
    });
  });

  it("throws on a non-append-only update so the caller can fall back", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.update("hello");
    await expect(live.update("goodbye")).rejects.toBeInstanceOf(NonAppendOnlyUpdateError);
  });

  it("cancel before begin is terminal and sends no stream_cancel", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.cancel("never started");
    expect(calls.cancel).toHaveLength(0);
    await expect(live.update("hi")).rejects.toThrow(/finalized or cancelled/);
  });

  it("cancel after begin sends stream_cancel, is idempotent, and is terminal", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.update("hi");
    await live.cancel("superseded");
    await live.cancel("again");
    expect(calls.cancel).toEqual([{ streamId: STREAM_ID, reason: "superseded" }]);
    expect(live.isActive).toBe(false);
    await expect(live.update("more")).rejects.toThrow(/finalized or cancelled/);
  });

  it("cancel waits for an in-flight stream_begin, sends stream_cancel, and blocks the original write", async () => {
    const calls = emptyCalls();
    const gated = gatedBeginClient(calls);
    const live = previewWithClient(gated.client);

    const updateCall = live.update("hi");
    expect(gated.beginCount()).toBe(1);
    const cancelCall = live.cancel("superseded");

    gated.releaseBegin();
    await expect(updateCall).rejects.toThrow(/finalized or cancelled/);
    await cancelCall;

    expect(calls.begin).toHaveLength(1);
    expect(calls.cancel).toEqual([{ streamId: STREAM_ID, reason: "superseded" }]);
    expect(calls.append).toEqual([]);
    expect(live.isActive).toBe(false);
  });

  it.each([
    ["appendDelta", (live: MarmotLivePreview) => live.appendDelta("hi"), (calls: Calls) => calls.append],
    ["status", (live: MarmotLivePreview) => live.status("thinking"), (calls: Calls) => calls.status],
    ["progress", (live: MarmotLivePreview) => live.progress("searching"), (calls: Calls) => calls.progress],
    ["finalize", (live: MarmotLivePreview) => live.finalize("done"), (calls: Calls) => calls.finalize],
  ])("does not send %s records after cancel wins the in-flight begin race", async (_name, startCall, records) => {
    const calls = emptyCalls();
    const gated = gatedBeginClient(calls);
    const live = previewWithClient(gated.client);

    const inFlightCall = startCall(live);
    expect(gated.beginCount()).toBe(1);
    const cancelCall = live.cancel("superseded");

    gated.releaseBegin();
    await expect(inFlightCall).rejects.toThrow(/finalized or cancelled/);
    await cancelCall;

    expect(calls.cancel).toEqual([{ streamId: STREAM_ID, reason: "superseded" }]);
    expect(records(calls)).toEqual([]);
    expect(calls.append).toEqual([]);
  });

  it("keeps cancel terminal when it waits on begin before a racing write registers", async () => {
    const calls = emptyCalls();
    const gated = gatedBeginClient(calls);
    const live = previewWithClient(gated.client);

    const beginCall = live.begin();
    expect(gated.beginCount()).toBe(1);
    const cancelCall = live.cancel("superseded");
    const updateExpectation = expect(live.update("hi")).rejects.toThrow(/finalized or cancelled/);

    gated.releaseBegin();
    await expect(beginCall).rejects.toThrow(/finalized or cancelled/);
    await updateExpectation;
    await cancelCall;

    expect(calls.begin).toHaveLength(1);
    expect(calls.cancel).toEqual([{ streamId: STREAM_ID, reason: "superseded" }]);
    expect(calls.append).toEqual([]);
    expect(live.isActive).toBe(false);
  });

  it("rejects update and finalize after finalize", async () => {
    const calls = emptyCalls();
    const live = preview(calls);
    await live.update("hello world");
    await live.finalize("hello world");
    await expect(live.update("hello world!")).rejects.toThrow(/finalized or cancelled/);
    await expect(live.finalize("hello world!")).rejects.toThrow(/finalized or cancelled/);
  });

  it("issues a single stream_begin for concurrent first calls", async () => {
    const calls = emptyCalls();
    // Gate streamBegin so both first callers reach it before either resolves.
    let releaseBegin: (() => void) | undefined;
    const beginGate = new Promise<void>((resolve) => {
      releaseBegin = resolve;
    });
    let beginCount = 0;
    const client = {
      async streamBegin(account: string, group: string, opts?: { quicCandidates?: Iterable<string> }) {
        beginCount += 1;
        await beginGate;
        const quic = [...(opts?.quicCandidates ?? [])];
        calls.begin.push({ account, group, quic });
        return {
          type: "stream_begun",
          stream_id_hex: STREAM_ID,
          start_message_id_hex: START_ID,
          quic_candidates: quic,
        };
      },
      async streamAppend(streamId: string, text: string) {
        calls.append.push({ streamId, text });
        return { type: "ack" };
      },
      async streamStatus(streamId: string, text: string) {
        calls.status.push({ streamId, text });
        return { type: "ack" };
      },
      async streamProgress(streamId: string, text: string) {
        calls.progress.push({ streamId, text });
        return { type: "ack" };
      },
      async streamFinalize(streamId: string, finalText: string, hash: string, count: number) {
        calls.finalize.push({ streamId, finalText, hash, count });
        return { type: "stream_finalized", stream_id_hex: streamId, message_ids_hex: [HEX32("ab")] };
      },
      async streamCancel() {
        return { type: "ack" };
      },
    } as unknown as StreamControlClient;

    const live = new MarmotLivePreview(client, {
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      quicCandidates: ["quic://broker:4450"],
    });

    // Two concurrent first calls race before any begin/prewarm.
    const statusCall = live.status("thinking");
    const progressCall = live.progress("searching");
    // Both should now be parked on the shared in-flight begin.
    releaseBegin?.();
    await Promise.all([statusCall, progressCall]);

    // Only one stream_begin should have been issued despite the race.
    expect(beginCount).toBe(1);
    expect(calls.begin).toHaveLength(1);
    expect(calls.status.map((c) => c.text)).toEqual(["thinking"]);
    expect(calls.progress.map((c) => c.text)).toEqual(["searching"]);
  });

  it("retries stream_begin after the first begin attempt fails", async () => {
    const calls = emptyCalls();
    let beginCount = 0;
    const client = {
      async streamBegin(account: string, group: string, opts?: { quicCandidates?: Iterable<string> }) {
        beginCount += 1;
        if (beginCount === 1) {
          throw new Error("begin boom");
        }
        const quic = [...(opts?.quicCandidates ?? [])];
        calls.begin.push({ account, group, quic });
        return {
          type: "stream_begun",
          stream_id_hex: STREAM_ID,
          start_message_id_hex: START_ID,
          quic_candidates: quic,
        };
      },
      async streamAppend(streamId: string, text: string) {
        calls.append.push({ streamId, text });
        return { type: "ack" };
      },
      async streamStatus() {
        return { type: "ack" };
      },
      async streamProgress() {
        return { type: "ack" };
      },
      async streamFinalize(streamId: string, finalText: string, hash: string, count: number) {
        calls.finalize.push({ streamId, finalText, hash, count });
        return { type: "stream_finalized", stream_id_hex: streamId, message_ids_hex: [HEX32("ab")] };
      },
      async streamCancel() {
        return { type: "ack" };
      },
    } as unknown as StreamControlClient;

    const live = new MarmotLivePreview(client, {
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      quicCandidates: [],
    });

    // A failed begin must clear the in-flight guard so a later call retries
    // rather than awaiting a permanently-rejected begin promise.
    await expect(live.update("hello world")).rejects.toThrow("begin boom");
    await live.update("hello world");
    await live.finalize("hello world");

    expect(beginCount).toBe(2);
    expect(calls.begin).toHaveLength(1);
    expect(calls.append.map((a) => a.text)).toEqual(["hello world"]);
    expect(calls.finalize[0]).toMatchObject({ hash: SINGLE_TEXT_HASH, count: 1 });
  });

  it("does not advance local state when streamAppend fails (retry-safe)", async () => {
    const calls = emptyCalls();
    let appendCalls = 0;
    const client = {
      async streamBegin() {
        return {
          type: "stream_begun",
          stream_id_hex: STREAM_ID,
          start_message_id_hex: START_ID,
          quic_candidates: [],
        };
      },
      async streamAppend(streamId: string, text: string) {
        appendCalls += 1;
        if (appendCalls === 1) {
          throw new Error("boom");
        }
        calls.append.push({ streamId, text });
        return { type: "ack" };
      },
      async streamStatus() {
        return { type: "ack" };
      },
      async streamProgress() {
        return { type: "ack" };
      },
      async streamFinalize(streamId: string, finalText: string, hash: string, count: number) {
        calls.finalize.push({ streamId, finalText, hash, count });
        return { type: "stream_finalized", stream_id_hex: streamId, message_ids_hex: [HEX32("ab")] };
      },
      async streamCancel() {
        return { type: "ack" };
      },
    } as unknown as StreamControlClient;

    const live = new MarmotLivePreview(client, {
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      quicCandidates: [],
    });

    await expect(live.update("hello world")).rejects.toThrow("boom");
    // The failed append must not have advanced local state; retrying the same
    // text reproduces the Rust single-chunk hash.
    await live.update("hello world");
    await live.finalize("hello world");
    expect(calls.append.map((a) => a.text)).toEqual(["hello world"]);
    expect(calls.finalize[0]).toMatchObject({ hash: SINGLE_TEXT_HASH, count: 1 });
  });
});
