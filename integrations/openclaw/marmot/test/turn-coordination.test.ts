import { describe, expect, it, vi } from "vitest";

import { AgentControlError, type MarmotAgentControlClient } from "../src/client.js";
import {
  createMarmotInboundDispatcher,
  MarmotReplySink,
  type MarmotDispatchClient,
  type MarmotSinkClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";
import { MarmotDispatchAmbiguousDeliveryError } from "../src/dispatch-errors.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import { createMarmotMessageAdapter } from "../src/outbound.js";
import * as turnDelivery from "../src/turn-delivery.js";
import {
  awaitTurnOutboundResolution,
  MarmotTurnDurableOwnershipError,
  recordTurnOutboundDelivery,
  runInMarmotTurn,
  type MarmotTurnRoute,
} from "../src/turn-delivery.js";

vi.mock("openclaw/plugin-sdk/channel-inbound", () => ({
  buildChannelInboundEventContext: vi.fn((params: unknown) => params),
  runChannelInboundEvent: vi.fn(
    async (params: {
      adapter: {
        resolveTurn: () => { runDispatch: () => Promise<unknown> };
      };
    }) => {
      return await params.adapter.resolveTurn().runDispatch();
    },
  ),
}));

const HEX = (b: string) => b.repeat(32);

function dualPathRuntime(
  onDispatch: (deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>) => Promise<void>,
): OpenClawChannelRuntime {
  return {
    routing: {
      resolveAgentRoute: () => ({
        agentId: "agent",
        accountId: "default",
        sessionKey: "agent:marmot",
      }),
    },
    session: {
      resolveStorePath: () => "/tmp/openclaw-marmot-turn-coordination",
      recordInboundSession: vi.fn(),
    },
    reply: {
      dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
        const deliver = (params as {
          dispatcherOptions: {
            deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
          };
        }).dispatcherOptions.deliver;
        await onDispatch(deliver);
      },
    },
  };
}

describe("inbound turn delivery coordination", () => {
  it("suppresses the sink final after a same-route message-tool send succeeds", async () => {
    const sendFinalCalls: { text: string; replyTo: string | null; key?: string }[] = [];
    const client = {
      async sendFinal(
        _accountIdHex: string,
        _groupIdHex: string,
        text: string,
        replyTo: string | null,
        idempotencyKey?: string,
      ) {
        sendFinalCalls.push({ text, replyTo, key: idempotencyKey });
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        await adapter.send!.text!({
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "tool-owned reply",
        } as never);
        await deliver({ text: "assistant final should be suppressed" }, { kind: "final" });
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual([
      { text: "tool-owned reply", replyTo: HEX("dd"), key: expect.any(String) },
    ]);
  });

  it("does not suppress the sink final after a definite same-route tool send failure", async () => {
    const sendFinalCalls: { text: string }[] = [];
    let toolAttempts = 0;
    const client = {
      async sendFinal(
        _accountIdHex: string,
        _groupIdHex: string,
        text: string,
      ) {
        sendFinalCalls.push({ text });
        toolAttempts += 1;
        if (toolAttempts === 1) {
          throw new AgentControlError("permanent", { retryable: false });
        }
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        await expect(
          adapter.send!.text!({
            cfg: {},
            accountId: "default",
            to: HEX("cc"),
            text: "failed tool send",
          } as never),
        ).rejects.toThrow("permanent");
        await deliver({ text: "sink-owned reply" }, { kind: "final" });
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls.map((call) => call.text)).toEqual([
      "failed tool send",
      "sink-owned reply",
    ]);
  });

  it("blocks the sink final after an ambiguous same-route tool send exhausts retries", async () => {
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        throw new AgentControlError("timed out waiting for send", { retryable: true });
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        await expect(
          adapter.send!.text!({
            cfg: {},
            accountId: "default",
            to: HEX("cc"),
            text: "ambiguous tool send",
          } as never),
        ).rejects.toThrow("timed out waiting for send");
        await deliver({ text: "must not duplicate" }, { kind: "final" });
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await expect(
      dispatch({
        accountIdHex: HEX("aa"),
        groupIdHex: HEX("cc"),
        messageIdHex: HEX("dd"),
        senderAccountIdHex: HEX("bb"),
        text: "hello",
      }),
    ).rejects.toBeInstanceOf(MarmotDispatchAmbiguousDeliveryError);

    expect(sendFinalCalls.length).toBeGreaterThan(1);
    expect(sendFinalCalls.every((text) => text === "ambiguous tool send")).toBe(true);
  });

  it("does not suppress the sink when the tool sends to another group", async () => {
    const sendFinalCalls: { groupIdHex: string; text: string }[] = [];
    const client = {
      async sendFinal(
        _accountIdHex: string,
        groupIdHex: string,
        text: string,
      ) {
        sendFinalCalls.push({ groupIdHex, text });
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        await adapter.send!.text!({
          cfg: {},
          accountId: "default",
          to: HEX("ff"),
          text: "out-of-band",
        } as never);
        await deliver({ text: "source reply" }, { kind: "final" });
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual([
      { groupIdHex: HEX("ff"), text: "out-of-band" },
      { groupIdHex: HEX("cc"), text: "source reply" },
    ]);
  });

  it("rejects a second same-route tool send within one turn", async () => {
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async () => {
        const ctx = {
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "first tool send",
        } as never;
        await adapter.send!.text!(ctx);
        await expect(
          adapter.send!.text!({
            cfg: {},
            accountId: "default",
            to: HEX("cc"),
            text: "duplicate tool send",
          } as never),
        ).rejects.toBeInstanceOf(MarmotTurnDurableOwnershipError);
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual(["first tool send"]);
  });

  it("rejects parallel same-route tool sends after the first claims durable ownership", async () => {
    let concurrent = 0;
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        concurrent += 1;
        sendFinalCalls.push(text);
        await new Promise((resolve) => setTimeout(resolve, 25));
        concurrent -= 1;
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async () => {
        const ctxA = {
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "parallel text A",
        } as never;
        const ctxB = {
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "parallel text B",
        } as never;
        const [first, second] = await Promise.allSettled([
          adapter.send!.text!(ctxA),
          adapter.send!.text!(ctxB),
        ]);
        expect([first.status, second.status].sort()).toEqual(["fulfilled", "rejected"]);
        const rejected = first.status === "rejected" ? first : second;
        expect(rejected.status).toBe("rejected");
        if (rejected.status === "rejected") {
          expect(rejected.reason).toBeInstanceOf(MarmotTurnDurableOwnershipError);
        }
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toHaveLength(1);
    expect(concurrent).toBe(0);
  });

  it("awaits an in-flight tool send before suppressing the sink final (tool-first race)", async () => {
    let releaseToolSend: (() => void) | undefined;
    const toolSendGate = new Promise<void>((resolve) => {
      releaseToolSend = resolve;
    });
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        if (text === "tool-owned reply") {
          await toolSendGate;
        }
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        const toolSend = adapter.send!.text!({
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "tool-owned reply",
        } as never);
        await vi.waitFor(() => sendFinalCalls.length === 1);
        const sinkCommit = deliver({ text: "sink must wait and suppress" }, { kind: "final" });
        await vi.waitFor(() => sendFinalCalls.length === 1);
        releaseToolSend?.();
        await sinkCommit;
        await toolSend;
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual(["tool-owned reply"]);
  });

  it("rejects a same-route tool send after the sink claims durable ownership (sink-first race)", async () => {
    let releaseSinkSend: (() => void) | undefined;
    const sinkSendGate = new Promise<void>((resolve) => {
      releaseSinkSend = resolve;
    });
    let notifySinkClaimed: (() => void) | undefined;
    const sinkClaimed = new Promise<void>((resolve) => {
      notifySinkClaimed = resolve;
    });
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        if (text === "sink-owned reply") {
          notifySinkClaimed?.();
          await sinkSendGate;
        }
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        const sinkSend = deliver({ text: "sink-owned reply" }, { kind: "final" });
        await sinkClaimed;
        await expect(
          adapter.send!.text!({
            cfg: {},
            accountId: "default",
            to: HEX("cc"),
            text: "tool must not send",
          } as never),
        ).rejects.toBeInstanceOf(MarmotTurnDurableOwnershipError);
        releaseSinkSend?.();
        await sinkSend;
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual(["sink-owned reply"]);
  });

  it("prevents duplicate connector calls when outbound starts in the sink gate gap", async () => {
    let releaseAfterResolution: (() => void) | undefined;
    const afterResolutionGate = new Promise<void>((resolve) => {
      releaseAfterResolution = resolve;
    });
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        const sinkCommit = deliver({ text: "sink must lose race" }, { kind: "final" });
        await afterResolutionGate;
        const toolSend = adapter.send!.text!({
          cfg: {},
          accountId: "default",
          to: HEX("cc"),
          text: "tool-owned reply",
        } as never);
        await Promise.all([sinkCommit, toolSend]);
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    const originalAcquire = turnDelivery.acquireSinkDeliveryOrSuppress;
    const acquireSpy = vi.spyOn(turnDelivery, "acquireSinkDeliveryOrSuppress");
    acquireSpy.mockImplementation(async (state) => {
      await awaitTurnOutboundResolution(state);
      releaseAfterResolution?.();
      await new Promise((resolve) => setImmediate(resolve));
      return originalAcquire(state);
    });

    try {
      await dispatch({
        accountIdHex: HEX("aa"),
        groupIdHex: HEX("cc"),
        messageIdHex: HEX("dd"),
        senderAccountIdHex: HEX("bb"),
        text: "hello",
      });
    } finally {
      acquireSpy.mockRestore();
    }

    expect(sendFinalCalls).toEqual(["tool-owned reply"]);
  });

});

describe("MarmotReplySink turn idempotency", () => {
  it("reuses the turn idempotency key for sink send_final", async () => {
    const keys: (string | undefined)[] = [];
    const client = {
      async sendFinal(
        _accountIdHex: string,
        _groupIdHex: string,
        _text: string,
        _replyTo: string | null,
        idempotencyKey?: string,
      ) {
        keys.push(idempotencyKey);
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
    } as unknown as MarmotSinkClient;
    const route: MarmotTurnRoute = {
      channelAccountId: "default",
      marmotAccountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      replyToMessageIdHex: HEX("dd"),
      idempotencyKey: "shared-turn-key",
    };
    await runInMarmotTurn(route, async () => {
      const sink = new MarmotReplySink({
        client,
        accountIdHex: HEX("aa"),
        groupIdHex: HEX("cc"),
        streamMode: "off",
        quicCandidates: [],
      });
      await sink.deliver({ text: "hello" }, { kind: "final" });
    });
    expect(keys).toEqual(["shared-turn-key"]);
  });
});

describe("outbound adapter omitted-target inheritance", () => {
  it("inherits route fields from the bound turn when to is runtime-undefined", async () => {
    const sendFinalCalls: {
      groupIdHex: string;
      text: string;
      replyTo: string | null;
      key?: string;
    }[] = [];
    const resolveCalls: { accountId?: string | null }[] = [];
    const client = {
      async sendFinal(
        _accountIdHex: string,
        groupIdHex: string,
        text: string,
        replyTo: string | null,
        idempotencyKey?: string,
      ) {
        sendFinalCalls.push({ groupIdHex, text, replyTo, key: idempotencyKey });
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async (_cfg, accountId) => {
        resolveCalls.push({ accountId });
        return {
          client: client as unknown as MarmotAgentControlClient,
          marmotAccountIdHex: HEX("aa"),
        };
      },
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async () => {
        await adapter.send!.text!({
          cfg: {},
          text: "inherited tool send",
        } as never);
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(resolveCalls).toEqual([{ accountId: "default" }]);
    expect(sendFinalCalls).toEqual([
      {
        groupIdHex: HEX("cc"),
        text: "inherited tool send",
        replyTo: HEX("dd"),
        key: expect.any(String),
      },
    ]);
  });

  it("keeps concurrent turns isolated across accounts and groups", async () => {
    const sendFinalCalls: { groupIdHex: string; text: string }[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, groupIdHex: string, text: string) {
        sendFinalCalls.push({ groupIdHex, text });
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const makeDispatch = (groupByte: string, accountId: string) =>
      createMarmotInboundDispatcher({
        cfg: {},
        runtimeChannel: dualPathRuntime(async () => {
          await adapter.send!.text!({
            cfg: {},
            text: `reply-${groupByte}`,
          } as never);
        }),
        client,
        channelAccountId: accountId,
        streamMode: "off",
        blockStreaming: false,
        quicCandidates: [],
        groupActivation: "always",
        mentionPatterns: [],
      });

    await Promise.all([
      makeDispatch("01", "acct-a")({
        accountIdHex: HEX("aa"),
        groupIdHex: HEX("01"),
        messageIdHex: HEX("d1"),
        senderAccountIdHex: HEX("bb"),
        text: "one",
      }),
      makeDispatch("02", "acct-b")({
        accountIdHex: HEX("aa"),
        groupIdHex: HEX("02"),
        messageIdHex: HEX("d2"),
        senderAccountIdHex: HEX("bb"),
        text: "two",
      }),
    ]);

    expect(sendFinalCalls).toEqual(
      expect.arrayContaining([
        { groupIdHex: HEX("01"), text: "reply-01" },
        { groupIdHex: HEX("02"), text: "reply-02" },
      ]),
    );
    expect(sendFinalCalls).toHaveLength(2);
  });

  it("allows a same-route tool send after an empty sink final", async () => {
    const sendFinalCalls: string[] = [];
    const client = {
      async sendFinal(_accountIdHex: string, _groupIdHex: string, text: string) {
        sendFinalCalls.push(text);
        return { type: "final_sent", message_ids_hex: [HEX("11")] };
      },
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: 2,
          is_direct: true,
          subject: null,
        };
      },
    } as unknown as MarmotDispatchClient;

    const adapter = createMarmotMessageAdapter({
      resolveTarget: async () => ({
        client: client as unknown as MarmotAgentControlClient,
        marmotAccountIdHex: HEX("aa"),
      }),
    });

    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: dualPathRuntime(async (deliver) => {
        await deliver({ text: "" }, { kind: "final" });
        await adapter.send!.text!({
          cfg: {},
          text: "tool recovery",
        } as never);
      }),
      client,
      channelAccountId: "default",
      streamMode: "off",
      blockStreaming: false,
      quicCandidates: [],
      groupActivation: "always",
      mentionPatterns: [],
    });

    await dispatch({
      accountIdHex: HEX("aa"),
      groupIdHex: HEX("cc"),
      messageIdHex: HEX("dd"),
      senderAccountIdHex: HEX("bb"),
      text: "hello",
    });

    expect(sendFinalCalls).toEqual(["tool recovery"]);
  });
});
