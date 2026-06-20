import { describe, expect, it, vi } from "vitest";

import type { StreamMode } from "../src/config.js";
import {
  createMarmotInboundDispatcher,
  MarmotReplySink,
  type MarmotSinkClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";

vi.mock("openclaw/plugin-sdk/channel-inbound", () => ({
  buildChannelInboundEventContext: vi.fn((params: unknown) => params),
  runChannelInboundEvent: vi.fn(
    async (params: { adapter: { resolveTurn: () => { runDispatch: () => Promise<unknown> } } }) => {
      await params.adapter.resolveTurn().runDispatch();
    },
  ),
}));

const HEX32 = (b: string) => b.repeat(32);
const STREAM_ID = HEX32("11");
const START_ID = HEX32("22");
// Rust-anchored hash for stream=0x11*32 start=0x22*32, appends "hel"/"lo"/" world".
const INCREMENTAL_HASH = "412b9bd20aedf322174fab2b1dee909992044fa166391027f4b8fb730d5c5a81";

interface Calls {
  sendFinal: { accountIdHex: string; text: string; replyTo: string | null }[];
  begin: number;
  append: string[];
  status: string[];
  progress: string[];
  finalize: { hash: string; count: number }[];
  cancel: string[];
}

function emptyCalls(): Calls {
  return { sendFinal: [], begin: 0, append: [], status: [], progress: [], finalize: [], cancel: [] };
}

function stubClient(calls: Calls): MarmotSinkClient {
  return {
    async sendFinal(_account: string, _group: string, text: string, replyTo?: string | null) {
      calls.sendFinal.push({ accountIdHex: _account, text, replyTo: replyTo ?? null });
      return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
    },
    async streamBegin() {
      calls.begin += 1;
      return {
        type: "stream_begun",
        stream_id_hex: STREAM_ID,
        start_message_id_hex: START_ID,
        quic_candidates: [],
      };
    },
    async streamAppend(_id: string, text: string) {
      calls.append.push(text);
      return { type: "ack" };
    },
    async streamStatus(_id: string, text: string) {
      calls.status.push(text);
      return { type: "ack" };
    },
    async streamProgress(_id: string, text: string) {
      calls.progress.push(text);
      return { type: "ack" };
    },
    async streamFinalize(_id: string, _final: string, hash: string, count: number) {
      calls.finalize.push({ hash, count });
      return { type: "stream_finalized", stream_id_hex: STREAM_ID, message_ids_hex: [HEX32("ab")] };
    },
    async streamCancel(_id: string, reason?: string | null) {
      calls.cancel.push(reason ?? "");
      return { type: "ack" };
    },
  } as unknown as MarmotSinkClient;
}

function makeSink(
  calls: Calls,
  opts: {
    streamMode?: StreamMode;
    quicCandidates?: string[];
    resolveFinalText?: () => Promise<string | undefined> | string | undefined;
  } = {},
): MarmotReplySink {
  return new MarmotReplySink({
    client: stubClient(calls),
    accountIdHex: HEX32("aa"),
    groupIdHex: HEX32("cc"),
    streamMode: opts.streamMode ?? "block",
    quicCandidates: opts.quicCandidates ?? ["quic://broker:4450"],
    resolveFinalText: opts.resolveFinalText,
  });
}

describe("MarmotReplySink", () => {
  it("sends a plain final when there were no preview blocks", async () => {
    const calls = emptyCalls();
    await makeSink(calls).deliver({ text: "hello world" }, { kind: "final" });
    expect(calls.begin).toBe(0);
    expect(calls.append).toEqual([]);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["hello world"]);
  });

  it("streams progressive blocks as append-only deltas and finalizes", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.deliver({ text: "hel" }, { kind: "block" });
    await sink.deliver({ text: "hello" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.sendFinal).toEqual([]);
  });

  it("streams fragment-style blocks as append-only deltas and finalizes", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.deliver({ text: "hel" }, { kind: "block" });
    await sink.deliver({ text: "lo" }, { kind: "block" });
    await sink.deliver({ text: " world" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.sendFinal).toEqual([]);
  });

  it("streams partial snapshots before delayed block chunks and finalizes", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.partial({ text: "hel" });
    await sink.partial({ text: "hello" });
    await sink.partial({ text: "hello world" });
    await sink.deliver({ text: "delayed block chunk" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.cancel).toEqual([]);
    expect(calls.sendFinal).toEqual([]);
  });

  it("streams partial append deltas even when snapshots are windowed", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.partial({ text: "hel", delta: "hel" });
    await sink.partial({ text: "lo window", delta: "lo" });
    await sink.partial({ text: "world window", delta: " world" });
    await sink.deliver({ text: "delayed block chunk" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.cancel).toEqual([]);
    expect(calls.sendFinal).toEqual([]);
  });

  it("streams delta-only partial payloads", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.partial({ delta: "hel" });
    await sink.partial({ delta: "lo" });
    await sink.partial({ delta: " world" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.sendFinal).toEqual([]);
  });

  it("lets block snapshots recover after a delta-less non-append partial", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.prewarm();
    await sink.partial({ text: "hel" });
    await sink.partial({ text: "window shifted" });
    await sink.deliver({ text: "hello" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.cancel).toEqual([]);
    expect(calls.finalize[0]).toEqual({ hash: INCREMENTAL_HASH, count: 3 });
    expect(calls.sendFinal).toEqual([]);
  });

  it("falls back durably when partial snapshots become non-append-only", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls, {
      streamMode: "partial",
      resolveFinalText: () => "hello complete answer",
    });
    await sink.partial({ text: "hello partial answer" });
    await sink.partial({ text: "window shifted", replace: true });
    await sink.flush();

    expect(calls.append).toEqual(["hello partial answer"]);
    expect(calls.cancel).toHaveLength(1);
    expect(calls.finalize).toEqual([]);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["hello complete answer"]);
  });

  it("can prewarm a live preview before answer text arrives", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls, { streamMode: "partial" });
    await sink.prewarm();
    await sink.partial({ text: "done" });
    await sink.flush();

    expect(calls.begin).toBe(1);
    expect(calls.status).toEqual([]);
    expect(calls.append).toEqual(["done"]);
    expect(calls.finalize[0]?.count).toBe(1);
    expect(calls.sendFinal).toEqual([]);
  });

  it("abandons partial-only block previews instead of committing tool acknowledgements", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls, { streamMode: "block" });
    await sink.prewarm();
    await sink.partial({ text: "Sent." });
    await sink.flush();

    expect(calls.append).toEqual(["Sent."]);
    expect(calls.cancel).toHaveLength(1);
    expect(calls.finalize).toEqual([]);
    expect(calls.sendFinal).toEqual([]);
  });

  it("streams tool deliveries as non-text progress and still finalizes answer text", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.deliver({ text: "searching" }, { kind: "tool" });
    await sink.deliver({ text: "answer" }, { kind: "block" });
    await sink.deliver({ text: "answer" }, { kind: "final" });

    expect(calls.progress).toEqual(["searching"]);
    expect(calls.append).toEqual(["answer"]);
    expect(calls.finalize[0]?.count).toBe(2);
    expect(calls.sendFinal).toEqual([]);
  });

  it("ignores blocks and sends a plain final when streaming is off", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls, { streamMode: "off" });
    await sink.deliver({ text: "hel" }, { kind: "block" });
    await sink.deliver({ text: "done" }, { kind: "final" });
    expect(calls.begin).toBe(0);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["done"]);
  });

  it("cancels the preview and falls back to send_final on a non-append-only block", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.deliver({ text: "hello" }, { kind: "block" });
    await sink.deliver({ text: "goodbye" }, { kind: "block" }); // not an extension
    await sink.deliver({ text: "goodbye" }, { kind: "final" });

    expect(calls.append).toEqual(["hello", "goodbye"]);
    expect(calls.cancel).toHaveLength(1);
    expect(calls.finalize).toEqual([]);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["goodbye"]);
  });

  it("falls back to a durable final when a preview append fails (e.g. broker unreachable)", async () => {
    const calls = emptyCalls();
    const client = stubClient(calls);
    // A QUIC/broker failure surfaces as a generic error, not a non-append-only
    // rejection — the reply must still be delivered, just without a live preview.
    client.streamAppend = (async () => {
      throw new Error("broker unreachable");
    }) as typeof client.streamAppend;
    const sink = new MarmotReplySink({
      client,
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      streamMode: "block",
      quicCandidates: ["quic://broker:4450"],
    });

    await sink.deliver({ text: "hel" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    expect(calls.finalize).toEqual([]);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["hello world"]);
  });

  it("falls back to a durable final when preview finalize fails", async () => {
    const calls = emptyCalls();
    const client = stubClient(calls);
    client.streamFinalize = (async () => {
      throw new Error("finalize failed");
    }) as typeof client.streamFinalize;
    const sink = new MarmotReplySink({
      client,
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      streamMode: "block",
      quicCandidates: ["quic://broker:4450"],
    });

    await sink.deliver({ text: "hel" }, { kind: "block" });
    await sink.deliver({ text: "hello" }, { kind: "block" });
    await sink.deliver({ text: "hello world" }, { kind: "final" });

    // The final suffix is appended before stream_finalize is attempted; the
    // finalize then throws, so we abandon and re-send the whole text durably.
    expect(calls.append).toEqual(["hel", "lo", " world"]);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["hello world"]);
  });

  it("commits the streamed reply at flush when the turn sends blocks but no final", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    // Block streaming delivered the whole answer as one block, with no trailing
    // `final` delivery — the live preview must still be finalized durably.
    await sink.deliver({ text: "the full answer" }, { kind: "block" });
    await sink.flush();

    expect(calls.begin).toBe(1);
    expect(calls.append).toEqual(["the full answer"]);
    expect(calls.finalize).toHaveLength(1);
    expect(calls.sendFinal).toEqual([]);
  });

  it("recovers the full transcript final for partial-mode windowed previews", async () => {
    const calls = emptyCalls();
    const full =
      "This is the complete recovered answer that OpenClaw persisted to the session transcript after the turn finished.";
    const sink = makeSink(calls, {
      streamMode: "partial",
      resolveFinalText: () => full,
    });

    await sink.deliver(
      { text: "This is the complete recovered answer that OpenClaw persisted..." },
      { kind: "block" },
    );
    await sink.deliver({ text: "window shifted and no longer starts at the prefix" }, { kind: "block" });
    await sink.flush();

    expect(calls.finalize).toEqual([]);
    expect(calls.cancel).toHaveLength(1);
    expect(calls.sendFinal.map((c) => c.text)).toEqual([full]);
  });

  it("flush sends a plain final for a blocks-only turn when streaming is off", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls, { streamMode: "off" });
    await sink.deliver({ text: "the answer" }, { kind: "block" });
    await sink.flush();

    expect(calls.begin).toBe(0);
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["the answer"]);
  });

  it("flush is a no-op once a final delivery has committed the reply", async () => {
    const calls = emptyCalls();
    const sink = makeSink(calls);
    await sink.deliver({ text: "answer" }, { kind: "final" });
    await sink.flush();
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["answer"]);
  });

  it("flush sends nothing when the turn produced no reply", async () => {
    const calls = emptyCalls();
    await makeSink(calls).flush();
    expect(calls).toEqual(emptyCalls());
  });

  it("ignores tool deliveries when streaming is off", async () => {
    const calls = emptyCalls();
    await makeSink(calls, { streamMode: "off" }).deliver({ text: "searching..." }, { kind: "tool" });
    expect(calls).toEqual(emptyCalls());
  });
});

describe("createMarmotInboundDispatcher", () => {
  it("enables OpenClaw block streaming when Marmot live block streaming is resolved on", async () => {
    const calls = emptyCalls();
    const captured: unknown[] = [];
    const routeInputs: unknown[] = [];
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: (input) => {
          routeInputs.push(input);
          return {
            agentId: "agent",
            accountId: "default",
            sessionKey: "agent:marmot",
          };
        },
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-test-session-store",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          captured.push(params);
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "done" }, { kind: "final" });
        },
      },
    };
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel,
      client: stubClient(calls),
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: true,
      quicCandidates: [],
    });

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "hello",
    });

    expect(routeInputs).toEqual([
      {
        cfg: {},
        channel: "marmot",
        accountId: "default",
        peer: { kind: "group", id: HEX32("cc") },
      },
    ]);
    expect(captured).toHaveLength(1);
    expect((captured[0] as { ctx: { accountId: string } }).ctx.accountId).toBe("default");
    expect(
      (captured[0] as { replyOptions: { disableBlockStreaming?: boolean } }).replyOptions
        .disableBlockStreaming,
    ).toBe(false);
    expect(calls.sendFinal[0]?.accountIdHex).toBe(HEX32("aa"));
    expect(calls.sendFinal.map((c) => c.text)).toEqual(["done"]);
  });
});
