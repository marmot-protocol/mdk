import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentControlEvent, MarmotAgentControlClient } from "../src/client.js";
import { createMarmotChannelPlugin } from "../src/channel.js";
import {
  createMarmotInboundDispatcher,
  type MarmotDispatchClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";
import {
  resetMarmotInboundAccountsForTests,
  startMarmotInbound,
} from "../src/inbound-runtime.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";

const HEX32 = (byte: string): string => byte.repeat(32);

afterEach(() => {
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
});

/**
 * Exercise Marmot's production adapters against the installed OpenClaw host.
 * This file is also run by openclaw-host-compat.sh against the supported beta.
 */
describe("installed OpenClaw inbound host contract", () => {
  it("runs Marmot's real dispatcher through the installed turn kernel", async () => {
    const deliverInboundReply = vi.fn(async () => ({
      status: "handled_visible" as const,
      delivery: {},
    }));
    const runDispatch = vi.fn(async (params: unknown) => {
      const deliver = (params as {
        dispatcherOptions: {
          deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
        };
      }).dispatcherOptions.deliver;
      await deliver({ text: "host-compatible reply" }, { kind: "final" });
      return { counts: {} };
    });
    const resolveStorePath = vi.fn((_store?: string, options?: unknown) => {
      const agentId = (options as { agentId?: string } | undefined)?.agentId;
      if (!agentId) {
        const error = new Error("Session store path requires an explicit agent id.");
        error.name = "SessionStoreAgentIdRequiredError";
        throw error;
      }
      return "/tmp/openclaw-marmot-host-contract";
    });
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot:host-contract",
        }),
      },
      session: {
        resolveStorePath,
        recordInboundSession: vi.fn(async () => undefined),
      },
      reply: { dispatchReplyWithBufferedBlockDispatcher: runDispatch },
    };
    const client = {
      timelineList: vi.fn(async (accountIdHex: string, groupIdHex: string) => ({
        type: "timeline_page" as const,
        account_id_hex: accountIdHex,
        group_id_hex: groupIdHex,
        messages: [],
        has_more_before: false,
        has_more_after: false,
      })),
    } as unknown as MarmotDispatchClient;
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel,
      client,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
      deliverInboundReply: deliverInboundReply as never,
    });

    await expect(
      dispatch({
        accountIdHex: HEX32("aa"),
        groupIdHex: HEX32("cc"),
        messageIdHex: HEX32("dd"),
        senderAccountIdHex: HEX32("bb"),
        text: "host contract",
      }),
    ).resolves.toBe(true);

    expect(runDispatch).toHaveBeenCalledOnce();
    expect(deliverInboundReply).toHaveBeenCalledOnce();
    expect(resolveStorePath).toHaveBeenCalledWith(undefined, { agentId: "agent" });
  });

  it("leaves generic sends to beta's durable core while owning delete", () => {
    const actions = createMarmotChannelPlugin().actions;

    expect(actions?.supportsAction?.({ action: "send" })).toBe(false);
    expect(actions?.supportsAction?.({ action: "delete" })).toBe(true);
  });

  const betaContract = process.env.OPENCLAW_HOST_COMPAT_EXPECT_FLUSH_PAIR === "1" ? it : it.skip;
  betaContract("dispatches a debounced batch through beta's lifecycle contract", async () => {
    const events: AgentControlEvent[] = ["first", "second"].map((text, index) => ({
      type: "inbound_message",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      message: {
        message_id_hex: HEX32(index === 0 ? "d1" : "d2"),
        sender: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
        text,
        recorded_at: 123 + index,
        media: [],
      },
    }));
    const client = {
      accountList: async () => ({
        type: "account_list" as const,
        accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
      }),
      async *subscribeInbound(
        _filter?: unknown,
        _signal?: AbortSignal,
        hooks?: { onReady?: () => void },
      ): AsyncGenerator<AgentControlEvent> {
        hooks?.onReady?.();
        yield* events;
        await new Promise<void>((resolve) => {
          if (_signal?.aborted) {
            resolve();
          } else {
            _signal?.addEventListener("abort", () => resolve(), { once: true });
          }
        });
      },
    } as unknown as MarmotAgentControlClient;
    const dispatched = vi.fn(async (_message: MarmotInboundMessage) => undefined);
    const stop = startMarmotInbound(
      {
        config: {
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false } },
        },
        logger: { info: () => undefined, warn: () => undefined },
      },
      dispatched,
      { clientFactory: () => client },
    );

    try {
      await vi.waitFor(() => expect(dispatched).toHaveBeenCalledOnce());
      expect(dispatched.mock.calls[0]?.[0]).toMatchObject({ text: "first\nsecond" });
    } finally {
      stop();
    }
  });
});
