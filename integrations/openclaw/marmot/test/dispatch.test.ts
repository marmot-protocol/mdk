import { beforeEach, describe, expect, it, vi } from "vitest";

import { AgentControlError, type AgentControlMediaRef } from "../src/client.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import {
  buildMarmotTurnConfig,
  createMarmotInboundDispatcher,
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
  opts: { isDirect?: boolean } = {},
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
