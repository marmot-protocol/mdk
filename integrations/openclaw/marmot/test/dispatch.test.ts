import { describe, expect, it, vi } from "vitest";

import type { StreamMode } from "../src/config.js";
import { AgentControlError, type AgentControlMediaRef } from "../src/client.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import {
  createMarmotInboundDispatcher,
  MarmotReplySink,
  type MarmotDispatchClient,
  type MarmotSinkClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";

vi.mock("openclaw/plugin-sdk/channel-inbound", () => ({
  buildChannelInboundEventContext: vi.fn((params: unknown) => params),
  runChannelInboundEvent: vi.fn(
    async (params: { adapter: { resolveTurn: () => { runDispatch: () => Promise<unknown> } } }) => {
      await params.adapter.resolveTurn().runDispatch();
    },
  ),
}));

vi.mock("openclaw/plugin-sdk/media-store", () => ({
  saveMediaBuffer: vi.fn(async (_buf: Buffer, ct?: string, _sub?: string, _max?: number, name?: string) => ({
    id: "id1",
    path: `/oc/media/inbound/${name}`,
    size: 4,
    contentType: ct,
  })),
}));

vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(async () => Buffer.from("x")),
  unlink: vi.fn(async () => {}),
}));

const buildCtxMock = vi.mocked(buildChannelInboundEventContext);

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

function stubClient(calls: Calls, opts: { isDirect?: boolean } = {}): MarmotSinkClient {
  return {
    async sendFinal(_account: string, _group: string, text: string, replyTo?: string | null) {
      calls.sendFinal.push({ accountIdHex: _account, text, replyTo: replyTo ?? null });
      return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
    },
    async groupInfo(accountIdHex: string, groupIdHex: string) {
      return {
        type: "group_info",
        account_id_hex: accountIdHex,
        group_id_hex: groupIdHex,
        member_count: opts.isDirect ? 2 : 5,
        is_direct: opts.isDirect ?? false,
        subject: null,
      };
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

  it("retries a retryable durable final, reusing one idempotency key per call", async () => {
    const keys: (string | undefined)[] = [];
    let attempts = 0;
    const client = {
      async sendFinal(
        _account: string,
        _group: string,
        _text: string,
        _replyTo?: string | null,
        idempotencyKey?: string,
      ) {
        keys.push(idempotencyKey);
        attempts += 1;
        if (attempts === 1) {
          throw new AgentControlError("transient", { code: "io_error", retryable: true });
        }
        return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
      },
    } as unknown as MarmotSinkClient;
    const sink = new MarmotReplySink({
      client,
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      streamMode: "off",
      quicCandidates: [],
    });

    await sink.deliver({ text: "hello world" }, { kind: "final" });
    expect(attempts).toBe(2);
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]); // same key reused across the retry
  });

  it("does not retry a non-retryable durable final and rethrows", async () => {
    let attempts = 0;
    const client = {
      async sendFinal() {
        attempts += 1;
        throw new AgentControlError("bad request", { code: "bad_request", retryable: false });
      },
    } as unknown as MarmotSinkClient;
    const sink = new MarmotReplySink({
      client,
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      streamMode: "off",
      quicCandidates: [],
    });

    await expect(sink.deliver({ text: "hello" }, { kind: "final" })).rejects.toThrow("bad request");
    expect(attempts).toBe(1);
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
      client: stubClient(calls) as unknown as MarmotDispatchClient,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: true,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
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
    // GAP-01: the durable reply threads to the triggering message id.
    expect(calls.sendFinal[0]?.replyTo).toBe(HEX32("dd"));
  });
});

describe("createMarmotInboundDispatcher activation gating", () => {
  function gatingRuntime(turnRan: { value: boolean }): OpenClawChannelRuntime {
    return {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-gating-test",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          turnRan.value = true;
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "ok" }, { kind: "final" });
        },
      },
    };
  }

  const baseMessage: MarmotInboundMessage = {
    accountIdHex: HEX32("aa"),
    groupIdHex: HEX32("cc"),
    messageIdHex: HEX32("dd"),
    senderAccountIdHex: HEX32("bb"),
    text: "just chatting amongst ourselves",
  };

  async function runCase(opts: {
    groupActivation: "mention" | "always";
    mentionPatterns?: string[];
    isDirect?: boolean;
    message?: Partial<MarmotInboundMessage>;
  }): Promise<boolean> {
    const turnRan = { value: false };
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: gatingRuntime(turnRan),
      client: stubClient(emptyCalls(), {
        isDirect: opts.isDirect,
      }) as unknown as MarmotDispatchClient,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: opts.groupActivation,
      mentionPatterns: opts.mentionPatterns ?? [],
    });
    await dispatch({ ...baseMessage, ...opts.message });
    return turnRan.value;
  }

  it("skips an unaddressed message in a multi-party group", async () => {
    expect(await runCase({ groupActivation: "mention", isDirect: false })).toBe(false);
  });

  it("replies in an effective DM (two members) even when unaddressed", async () => {
    expect(await runCase({ groupActivation: "mention", isDirect: true })).toBe(true);
  });

  it("replies when the agent is mentioned (p-tagged)", async () => {
    expect(
      await runCase({ groupActivation: "mention", isDirect: false, message: { mentionsSelf: true } }),
    ).toBe(true);
  });

  it("replies when a configured trigger phrase matches", async () => {
    expect(
      await runCase({
        groupActivation: "mention",
        mentionPatterns: ["marvin"],
        isDirect: false,
        message: { text: "hey Marvin, can you help?" },
      }),
    ).toBe(true);
  });

  it("replies to everything when groupActivation is always", async () => {
    expect(await runCase({ groupActivation: "always", isDirect: false })).toBe(true);
  });
});

describe("createMarmotInboundDispatcher activation cache", () => {
  function cachingRuntime(turns: { count: number }): OpenClawChannelRuntime {
    return {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-cache-test",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          turns.count += 1;
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "ok" }, { kind: "final" });
        },
      },
    };
  }

  /** A control client whose `groupInfo` is call-counted and (optionally) toggleable/erroring. */
  function countingClient(opts: {
    isDirect: boolean | (() => boolean);
    throwError?: () => boolean;
  }): { client: MarmotDispatchClient; groupInfoCalls: () => number } {
    let calls = 0;
    const client = {
      async sendFinal() {
        return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        calls += 1;
        if (opts.throwError?.()) {
          throw new Error("group_info failed");
        }
        const isDirect = typeof opts.isDirect === "function" ? opts.isDirect() : opts.isDirect;
        return {
          type: "group_info" as const,
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: isDirect ? 2 : 5,
          is_direct: isDirect,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;
    return { client, groupInfoCalls: () => calls };
  }

  const baseMessage: MarmotInboundMessage = {
    accountIdHex: HEX32("aa"),
    groupIdHex: HEX32("cc"),
    messageIdHex: HEX32("dd"),
    senderAccountIdHex: HEX32("bb"),
    text: "just chatting amongst ourselves",
  };

  function makeDispatch(client: MarmotDispatchClient, turns: { count: number }) {
    return createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: cachingRuntime(turns),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "mention",
      mentionPatterns: [],
    });
  }

  it("queries group membership once and reuses the cached is_direct fact", async () => {
    const turns = { count: 0 };
    const { client, groupInfoCalls } = countingClient({ isDirect: false });
    const dispatch = makeDispatch(client, turns);

    await dispatch({ ...baseMessage, messageIdHex: HEX32("01") });
    await dispatch({ ...baseMessage, messageIdHex: HEX32("02") });
    await dispatch({ ...baseMessage, messageIdHex: HEX32("03") });

    // One MLS state read for three ambient messages; none ran a turn (multi-party, unaddressed).
    expect(groupInfoCalls()).toBe(1);
    expect(turns.count).toBe(0);
  });

  it("does not consult the cache for an addressed message (no membership read)", async () => {
    const turns = { count: 0 };
    const { client, groupInfoCalls } = countingClient({ isDirect: false });
    const dispatch = makeDispatch(client, turns);

    await dispatch({ ...baseMessage, mentionsSelf: true });

    expect(groupInfoCalls()).toBe(0);
    expect(turns.count).toBe(1);
  });

  it("re-reads membership after the activation cache is invalidated", async () => {
    const turns = { count: 0 };
    // Membership flips from multi-party to a two-member DM between the two reads.
    let direct = false;
    const { client, groupInfoCalls } = countingClient({ isDirect: () => direct });
    const dispatch = makeDispatch(client, turns);

    expect(await runTurn(dispatch, turns, { ...baseMessage, messageIdHex: HEX32("01") })).toBe(
      false,
    );
    expect(groupInfoCalls()).toBe(1);

    // A membership change invalidates the cached fact and flips is_direct.
    direct = true;
    dispatch.invalidateGroupActivation(baseMessage.accountIdHex, baseMessage.groupIdHex);

    expect(await runTurn(dispatch, turns, { ...baseMessage, messageIdHex: HEX32("02") })).toBe(true);
    expect(groupInfoCalls()).toBe(2);
  });

  it("clearGroupActivationCache drops every cached fact", async () => {
    const turns = { count: 0 };
    const { client, groupInfoCalls } = countingClient({ isDirect: false });
    const dispatch = makeDispatch(client, turns);

    await dispatch({ ...baseMessage, messageIdHex: HEX32("01") });
    expect(groupInfoCalls()).toBe(1);

    dispatch.clearGroupActivationCache();
    await dispatch({ ...baseMessage, messageIdHex: HEX32("02") });
    expect(groupInfoCalls()).toBe(2);
  });

  it("fails closed (skips the turn) when the membership lookup errors", async () => {
    const turns = { count: 0 };
    const { client, groupInfoCalls } = countingClient({ isDirect: true, throwError: () => true });
    const dispatch = makeDispatch(client, turns);

    await dispatch({ ...baseMessage });

    // An unaddressed message with an unresolvable membership must NOT barge in.
    expect(turns.count).toBe(0);
    expect(groupInfoCalls()).toBe(1);
  });

  it("does not cache a membership-lookup error (retries on the next message)", async () => {
    const turns = { count: 0 };
    let fail = true;
    const { client, groupInfoCalls } = countingClient({ isDirect: true, throwError: () => fail });
    const dispatch = makeDispatch(client, turns);

    expect(await runTurn(dispatch, turns, { ...baseMessage, messageIdHex: HEX32("01") })).toBe(
      false,
    );
    expect(groupInfoCalls()).toBe(1);

    // The error was not cached: the next message re-reads, succeeds, and (DM) replies.
    fail = false;
    expect(await runTurn(dispatch, turns, { ...baseMessage, messageIdHex: HEX32("02") })).toBe(true);
    expect(groupInfoCalls()).toBe(2);
  });

  /** Dispatch a message and report whether an agent turn ran (the gate let it through). */
  async function runTurn(
    dispatch: (message: MarmotInboundMessage) => Promise<void>,
    turns: { count: number },
    message: MarmotInboundMessage,
  ): Promise<boolean> {
    const before = turns.count;
    await dispatch(message);
    return turns.count > before;
  }
});

describe("createMarmotInboundDispatcher inbound media", () => {
  function mediaRuntime(): OpenClawChannelRuntime {
    return {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-media-test",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "ok" }, { kind: "final" });
        },
      },
    };
  }

  function imageRef(byte: string, mediaType = "image/png"): AgentControlMediaRef {
    return {
      media_type: mediaType,
      file_name: `img-${byte}.png`,
      ciphertext_sha256: HEX32(byte),
      plaintext_sha256: HEX32(byte),
      nonce_hex: HEX32(byte),
      version: "1",
      source_epoch: 0,
      locators: [],
    };
  }

  function mediaClient(
    downloads: AgentControlMediaRef[],
    opts: { fail?: boolean } = {},
  ): MarmotDispatchClient {
    return {
      async sendFinal() {
        return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 5,
          is_direct: false,
          subject: null,
        };
      },
      async downloadMedia(_account: string, _group: string, media: AgentControlMediaRef) {
        downloads.push(media);
        if (opts.fail) {
          throw new AgentControlError("download failed", { code: "io_error" });
        }
        return {
          type: "media_downloaded",
          path: `/tmp/marmot-dl/${media.file_name}`,
          media_type: media.media_type,
          file_name: media.file_name,
          size_bytes: 10,
        };
      },
    } as unknown as MarmotDispatchClient;
  }

  function makeDispatch(client: MarmotDispatchClient) {
    return createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: mediaRuntime(),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });
  }

  it("downloads inbound media and passes local file facts into the context builder", async () => {
    buildCtxMock.mockClear();
    const downloads: AgentControlMediaRef[] = [];
    const ref = imageRef("e1");
    const dispatch = makeDispatch(mediaClient(downloads));

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "look",
      media: [ref],
    });

    expect(downloads).toEqual([ref]);
    const ctxArg = buildCtxMock.mock.calls[0]?.[0] as { media?: unknown };
    // The fact path is the OpenClaw media-store staged path (allowlisted for both
    // native vision and the agent's `image` tool), not the raw dm-agent temp path.
    expect(ctxArg.media).toEqual([
      {
        path: `/oc/media/inbound/${ref.file_name}`,
        contentType: "image/png",
        kind: "image",
        messageId: HEX32("dd"),
      },
    ]);
  });

  it("classifies non-image media types and omits failed downloads", async () => {
    buildCtxMock.mockClear();
    const downloads: AgentControlMediaRef[] = [];
    const ok = imageRef("e2", "application/pdf");
    const dispatch = makeDispatch(mediaClient(downloads));

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "doc",
      media: [ok],
    });

    const ctxArg = buildCtxMock.mock.calls[0]?.[0] as { media?: Array<{ kind?: string }> };
    expect(ctxArg.media?.[0]?.kind).toBe("document");
  });

  it("omits the media field entirely when every download fails", async () => {
    buildCtxMock.mockClear();
    const downloads: AgentControlMediaRef[] = [];
    const dispatch = makeDispatch(mediaClient(downloads, { fail: true }));

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "broken",
      media: [imageRef("e3")],
    });

    expect(downloads).toHaveLength(1);
    const ctxArg = buildCtxMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("media" in ctxArg).toBe(false);
  });

  it("does not call downloadMedia for a message with no media", async () => {
    buildCtxMock.mockClear();
    const downloads: AgentControlMediaRef[] = [];
    const dispatch = makeDispatch(mediaClient(downloads));

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "no media",
    });

    expect(downloads).toHaveLength(0);
    const ctxArg = buildCtxMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("media" in ctxArg).toBe(false);
  });
});
