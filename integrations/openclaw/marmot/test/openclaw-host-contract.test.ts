import { describe, expect, it, vi } from "vitest";

import { runChannelInboundEvent } from "openclaw/plugin-sdk/channel-inbound";

/**
 * Exercise the installed OpenClaw turn kernel rather than a mocked SDK seam.
 * This file is also run by openclaw-host-compat.sh against the supported beta.
 */
describe("installed OpenClaw inbound host contract", () => {
  it("accepts Marmot's lifecycle-neutral prepared dispatch", async () => {
    const runDispatch = vi.fn(async () => ({ counts: {} }));

    await runChannelInboundEvent({
      channel: "marmot",
      accountId: "default",
      raw: {},
      adapter: {
        ingest: () => ({
          id: "host-contract-message",
          rawText: "host contract",
          textForAgent: "host contract",
        }),
        resolveTurn: () => ({
          channel: "marmot",
          accountId: "default",
          routeSessionKey: "agent:marmot:host-contract",
          storePath: "/tmp/openclaw-marmot-host-contract",
          ctxPayload: {},
          recordInboundSession: async () => undefined,
          runDispatchLifecycle: {
            turnAdoptionLifecycle: undefined,
            onDispatchSkipped: async () => undefined,
          },
          runDispatch,
        }),
      },
    } as never);

    expect(runDispatch).toHaveBeenCalledOnce();
  });
});
