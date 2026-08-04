import { beforeEach, describe, expect, it, vi } from "vitest";

import { AgentControlError, type AgentControlMediaRef } from "../src/client.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import {
  buildMarmotTurnConfig,
  createMarmotInboundDispatcher,
  TIMELINE_CONTEXT_BYTE_LIMIT,
  TIMELINE_CONTEXT_MESSAGE_LIMIT,
  type MarmotDispatchClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";
import { deliverInboundReplyWithMessageSendContext } from "openclaw/plugin-sdk/channel-outbound";

vi.mock("openclaw/plugin-sdk/channel-inbound", () => ({
  buildChannelInboundEventContext: vi.fn((params: unknown) => params),
  runChannelInboundEvent: vi.fn(
    async (params: { adapter: { resolveTurn: () => { runDispatch: () => Promise<unknown> } } }) => {
      await params.adapter.resolveTurn().runDispatch();
    },
  ),
}));

vi.mock("openclaw/plugin-sdk/channel-outbound", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("openclaw/plugin-sdk/channel-outbound")>();
  return {
    ...actual,
    deliverInboundReplyWithMessageSendContext: vi.fn(async () => ({
      status: "handled_visible",
      delivery: {},
    })),
  };
});

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
const durableDeliveryMock = vi.mocked(deliverInboundReplyWithMessageSendContext);

beforeEach(() => {
  durableDeliveryMock.mockClear();
});

const HEX32 = (b: string) => b.repeat(32);

describe("buildMarmotTurnConfig", () => {
  it("denies sessions_send without mutating existing tool policy", () => {
    const base = { tools: { deny: ["dangerous_tool"] }, marker: true };
    const configured = buildMarmotTurnConfig(base);

    expect(configured).toMatchObject({
      marker: true,
      tools: { deny: ["dangerous_tool", "sessions_send"] },
    });
    expect(base.tools.deny).toEqual(["dangerous_tool"]);
  });
});

interface Calls {
  sendFinal: { accountIdHex: string; text: string; replyTo: string | null }[];
}

function emptyCalls(): Calls {
  return { sendFinal: [] };
}

function stubClient(
  calls: Calls,
  opts: { isDirect?: boolean; history?: unknown[] } = {},
): MarmotDispatchClient {
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
    async timelineList(accountIdHex: string, groupIdHex: string) {
      return {
        type: "timeline_page",
        account_id_hex: accountIdHex,
        group_id_hex: groupIdHex,
        messages: opts.history ?? [],
        has_more_before: false,
        has_more_after: false,
      };
    },
  } as unknown as MarmotDispatchClient;
}
describe("createMarmotInboundDispatcher", () => {
  it("routes a final through OpenClaw's durable message context with streaming disabled", async () => {
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
    ).toBe(true);
    expect(
      (captured[0] as { replyOptions: { sourceReplyDeliveryMode?: string } }).replyOptions
        .sourceReplyDeliveryMode,
    ).toBe("automatic");
    expect(calls.sendFinal).toEqual([]);
    expect(durableDeliveryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        channel: "marmot",
        accountId: "default",
        agentId: "agent",
        payload: { text: "done" },
        replyToId: HEX32("dd"),
        ctxPayload: expect.objectContaining({
          reply: expect.objectContaining({ to: HEX32("cc") }),
        }),
      }),
    );
  });

  it("maps authenticated time, native quote, and ambient facts into supplemental context", async () => {
    buildCtxMock.mockClear();
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-rich-context",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: vi.fn(async () => undefined),
      },
    };
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel,
      client: stubClient(emptyCalls(), {
        history: [
          {
            message_id_hex: HEX32("10"),
            sender: {
              account_id_hex: HEX32("bb"),
              display_name: "Alice",
              is_self: false,
            },
            direction: "received",
            kind: 9,
            recorded_at: 1_720_999_800,
            observed_at: 1_720_999_801,
            availability: "available",
            text: "earlier question",
            text_truncated: false,
            reply_to_message_id_hex: null,
            attachments: [],
            attachments_truncated: false,
            reactions: [],
            reactions_truncated: false,
          },
        ],
      }) as unknown as MarmotDispatchClient,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "new message",
      recordedAt: 1_721_000_000,
      replyToMessageIdHex: HEX32("11"),
      replyTo: {
        message_id_hex: HEX32("11"),
        availability: "available",
        sender: {
          account_id_hex: HEX32("aa"),
          display_name: "Agent",
          is_self: true,
        },
        recorded_at: 1_720_999_900,
        text_excerpt: "quoted body",
        text_truncated: false,
        attachments: [{ media_type: "image/png", file_name: "quote.png" }],
        attachments_truncated: false,
      },
      ambientContext: [
        {
          type: "reaction_added",
          account_id_hex: HEX32("aa"),
          group_id_hex: HEX32("cc"),
          event_id_hex: HEX32("22"),
          target_message_id_hex: HEX32("11"),
          actor: {
            account_id_hex: HEX32("bb"),
            display_name: "Alice",
            is_self: false,
          },
          emoji: "👍",
          recorded_at: 1_721_000_001,
          target: {
            message_id_hex: HEX32("11"),
            availability: "available",
            text_excerpt: "quoted body",
            text_truncated: false,
            attachments_truncated: false,
          },
        },
      ],
    });

    const context = buildCtxMock.mock.calls.at(-1)?.[0] as unknown as {
      timestamp: number;
      reply: { replyToId: string };
      suppressSelfQuoteBody: boolean;
      supplemental: {
        quote: {
          id: string;
          body: string;
          sender: string;
          isQuote: boolean;
          isSelf: boolean;
        };
        untrustedContext: Array<{ type: string; payload: unknown }>;
      };
    };
    expect(context.timestamp).toBe(1_721_000_000_000);
    expect(context.reply.replyToId).toBe(HEX32("11"));
    expect(context.suppressSelfQuoteBody).toBe(false);
    expect(context.supplemental.quote).toEqual({
      id: HEX32("11"),
      body: "quoted body",
      sender: "Agent",
      isQuote: true,
      isSelf: true,
    });
    expect(context.supplemental.untrustedContext).toEqual([
      expect.objectContaining({
        type: "referenced_message",
        payload: expect.objectContaining({
          message_id_hex: HEX32("11"),
          sender: expect.objectContaining({ account_id_hex: HEX32("aa") }),
          text_excerpt: "quoted body",
          attachments: [{ media_type: "image/png", file_name: "quote.png" }],
        }),
      }),
      expect.objectContaining({
        type: "chat_window",
        payload: expect.objectContaining({
          relation: "before_current_message",
          messages: [
            expect.objectContaining({
              message_id_hex: HEX32("10"),
              sender: expect.objectContaining({ display_name: "Alice" }),
              text: "earlier question",
            }),
          ],
        }),
      }),
      expect.objectContaining({ type: "reaction_added" }),
    ]);
  });

  it("keeps three sequential replies bound to the same Marmot group", async () => {
    const groupIdHex = HEX32("cc");
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-sequential-test",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "reply" }, { kind: "final" });
        },
      },
    };
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel,
      client: stubClient(emptyCalls()) as unknown as MarmotDispatchClient,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
    });

    for (const byte of ["d1", "d2", "d3"]) {
      await dispatch({
        accountIdHex: HEX32("aa"),
        groupIdHex,
        messageIdHex: HEX32(byte),
        senderAccountIdHex: HEX32("bb"),
        text: "hello",
      });
    }

    expect(durableDeliveryMock).toHaveBeenCalledTimes(3);
    expect(
      durableDeliveryMock.mock.calls.map(([params]) => ({
        to: (params.ctxPayload as unknown as { reply: { to: string } }).reply.to,
        replyToId: params.replyToId,
      })),
    ).toEqual(
      ["d1", "d2", "d3"].map((byte) => ({
        to: groupIdHex,
        replyToId: HEX32(byte),
      })),
    );
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
    dispatch: (message: MarmotInboundMessage) => Promise<boolean | void>,
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
    // native vision and the agent's `image` tool), not the raw wn-agent temp path.
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

describe("timeline context budget", () => {
  interface ChatWindowEntry {
    label: string;
    source: string;
    type: string;
    payload: {
      order: string;
      relation: string;
      messages: Array<Record<string, unknown>>;
      messages_truncated?: boolean;
      omitted_message_count?: number;
      oversized_message_count?: number;
    };
  }

  const utf8Bytes = (value: unknown): number =>
    Buffer.byteLength(JSON.stringify(value), "utf8");

  async function renderTimelineEntry(history: unknown[]): Promise<ChatWindowEntry | undefined> {
    buildCtxMock.mockClear();
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-history-budget",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: vi.fn(async () => undefined),
      },
    };
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel,
      client: stubClient(emptyCalls(), { history }) as unknown as MarmotDispatchClient,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      senderAccountIdHex: HEX32("bb"),
      text: "ping",
      recordedAt: 1_721_000_000,
    });

    const context = buildCtxMock.mock.calls.at(-1)?.[0] as unknown as {
      supplemental?: { untrustedContext?: ChatWindowEntry[] };
    };
    return context.supplemental?.untrustedContext?.find((entry) => entry.type === "chat_window");
  }

  it("passes a small page through without truncation metadata", async () => {
    const messages = [0, 1, 2].map((index) => ({
      message_id_hex: `${index}`,
      text: `message-${index}`,
    }));

    const entry = await renderTimelineEntry(messages);

    expect(entry?.payload.messages).toEqual(messages);
    expect(entry?.payload).not.toHaveProperty("messages_truncated");
    expect(utf8Bytes(entry)).toBeLessThanOrEqual(TIMELINE_CONTEXT_BYTE_LIMIT);
  });

  it("omits one oversized record rather than exceeding the budget", async () => {
    const entry = await renderTimelineEntry([
      { message_id_hex: "newest", text: "🙂".repeat(10_000) },
    ]);

    expect(entry?.payload.messages).toEqual([]);
    expect(entry?.payload.omitted_message_count).toBe(1);
    expect(entry?.payload.oversized_message_count).toBe(1);
    expect(utf8Bytes(entry)).toBeLessThanOrEqual(TIMELINE_CONTEXT_BYTE_LIMIT);
  });

  it("counts multiple oversized records dropped oldest-first", async () => {
    const entry = await renderTimelineEntry([
      { message_id_hex: "old-1", text: "🙂".repeat(10_000) },
      { message_id_hex: "old-2", text: "🙂".repeat(10_000) },
      { message_id_hex: "newest", text: "kept" },
    ]);

    expect(entry?.payload.messages.map((message) => message.message_id_hex)).toEqual(["newest"]);
    expect(entry?.payload.omitted_message_count).toBe(2);
    expect(entry?.payload.oversized_message_count).toBe(2);
    expect(JSON.stringify(entry)).not.toContain("old-1");
    expect(JSON.stringify(entry)).not.toContain("old-2");
  });

  it("counts oversized records outside the count window", async () => {
    const entry = await renderTimelineEntry(
      Array.from({ length: TIMELINE_CONTEXT_MESSAGE_LIMIT + 1 }, (_, index) => ({
        message_id_hex: `${index}`,
        text: "🙂".repeat(10_000),
      })),
    );

    expect(entry?.payload.messages).toEqual([]);
    expect(entry?.payload.omitted_message_count).toBe(TIMELINE_CONTEXT_MESSAGE_LIMIT + 1);
    expect(entry?.payload.oversized_message_count).toBe(TIMELINE_CONTEXT_MESSAGE_LIMIT + 1);
  });

  it("does not misclassify a record displaced by aggregate metadata", async () => {
    const finalMessage: { message_id_hex: string; text: string } = {
      message_id_hex: "final",
      text: "",
    };
    const referenceEntry = {
      label: "Marmot conversation history",
      source: "marmot",
      type: "chat_window",
      payload: {
        order: "chronological",
        relation: "before_current_message",
        messages: [finalMessage],
        messages_truncated: true,
        omitted_message_count: 1,
      },
    };
    finalMessage.text = "x".repeat(TIMELINE_CONTEXT_BYTE_LIMIT - utf8Bytes(referenceEntry));
    // Sanity: as the sole retained record (with omission metadata) it exactly fits.
    expect(utf8Bytes(referenceEntry)).toBeLessThanOrEqual(TIMELINE_CONTEXT_BYTE_LIMIT);

    const entry = await renderTimelineEntry([
      { message_id_hex: "oversized", text: "🙂".repeat(10_000) },
      ...Array.from({ length: TIMELINE_CONTEXT_MESSAGE_LIMIT - 1 }, (_, index) => ({
        message_id_hex: `small-${index}`,
        text: "",
      })),
      finalMessage,
    ]);

    expect(entry?.payload.messages).toEqual([]);
    expect(entry?.payload.omitted_message_count).toBe(TIMELINE_CONTEXT_MESSAGE_LIMIT + 1);
    expect(entry?.payload.oversized_message_count).toBe(1);
  });

  it("retains only the newest records from a twenty-record page", async () => {
    const messageId = (index: number) => index.toString(16).padStart(64, "0");
    const messages = Array.from({ length: 20 }, (_, index) => ({
      message_id_hex: messageId(index),
      text: "x".repeat(1_500),
    }));

    const entry = await renderTimelineEntry(messages);

    expect(entry?.payload.messages.map((message) => message.message_id_hex)).toEqual(
      Array.from({ length: TIMELINE_CONTEXT_MESSAGE_LIMIT }, (_, index) =>
        messageId(20 - TIMELINE_CONTEXT_MESSAGE_LIMIT + index),
      ),
    );
    expect(entry?.payload.omitted_message_count).toBe(20 - TIMELINE_CONTEXT_MESSAGE_LIMIT);
    expect(entry?.payload).not.toHaveProperty("oversized_message_count");
    expect(utf8Bytes(entry)).toBeLessThanOrEqual(TIMELINE_CONTEXT_BYTE_LIMIT);
  });
});
