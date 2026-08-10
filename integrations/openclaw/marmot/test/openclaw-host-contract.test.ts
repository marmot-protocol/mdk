import { describe, expect, it, vi } from "vitest";

import {
  createMarmotInboundDispatcher,
  type MarmotDispatchClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";
import {
  createCompatibleInboundDebounceFlush,
  createCompatibleInboundDebouncer,
  type CompatibleInboundDebounceFlush,
} from "../src/inbound-runtime.js";

const HEX32 = (byte: string): string => byte.repeat(32);

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
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot:host-contract",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-host-contract",
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
  });

  const betaContract = process.env.OPENCLAW_HOST_COMPAT_EXPECT_FLUSH_PAIR === "1" ? it : it.skip;
  betaContract("returns beta's usable debounce admission and completion pair", async () => {
    let observedFlush: CompatibleInboundDebounceFlush | Promise<void> | undefined;
    const dispatched = vi.fn(async () => undefined);
    const debouncer = createCompatibleInboundDebouncer<string>({
      debounceMs: 1,
      buildKey: () => "group",
      onFlush: (items, createFlush) => {
        observedFlush = createCompatibleInboundDebounceFlush(items, dispatched, createFlush);
        return observedFlush;
      },
    });

    await debouncer.enqueue("message");
    await debouncer.flushKey("group");

    expect(observedFlush).toEqual({
      admission: expect.any(Promise),
      completion: expect.any(Promise),
    });
    const lifecycle = observedFlush as CompatibleInboundDebounceFlush;
    await expect(lifecycle.admission).resolves.toBeUndefined();
    await expect(lifecycle.completion).resolves.toBeUndefined();
    expect(dispatched).toHaveBeenCalledWith(["message"]);
  });
});
