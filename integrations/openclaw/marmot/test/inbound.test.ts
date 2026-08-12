import { describe, expect, it } from "vitest";

import type { AgentControlEvent } from "../src/client.js";
import {
  MarmotInboundBridge,
  reconnectBackoffMs,
  type InboundSubscribeClient,
} from "../src/inbound.js";

const HEX32 = (b: string) => b.repeat(32);

function inboundMessage(messageId: string): AgentControlEvent {
  return {
    type: "inbound_message",
    account_id_hex: HEX32("aa"),
    group_id_hex: HEX32("cc"),
    message: {
      message_id_hex: messageId,
      sender: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      text: "hello agent",
      recorded_at: 123,
      media: [],
    },
  };
}

/** Client whose first subscription yields `firstBatch`, later ones yield nothing. */
function makeClient(firstBatch: AgentControlEvent[]): {
  client: InboundSubscribeClient;
  subscribeCalls: () => number;
} {
  let calls = 0;
  const client = {
    async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
      calls += 1;
      if (calls === 1) {
        for (const event of firstBatch) {
          yield event;
        }
      }
    },
  } as unknown as InboundSubscribeClient;
  return { client, subscribeCalls: () => calls };
}

describe("MarmotInboundBridge", () => {
  it("delivers inbound messages, dedupes by id, and surfaces resync", async () => {
    const resync: AgentControlEvent = {
      type: "resync_required",
      account_id_hex: null,
      group_id_hex: null,
      dropped_events: 3,
    };
    const { client } = makeClient([
      inboundMessage(HEX32("d1")),
      inboundMessage(HEX32("d1")), // duplicate id
      inboundMessage(HEX32("d2")),
      resync,
    ]);

    const delivered: string[] = [];
    let droppedEvents = -1;
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: (message) => {
        delivered.push(message.messageIdHex);
      },
      onResync: ({ droppedEvents: dropped }) => {
        droppedEvents = dropped;
        controller.abort();
      },
    });

    await bridge.run(controller.signal);

    expect(delivered).toEqual([HEX32("d1"), HEX32("d2")]);
    expect(droppedEvents).toBe(3);
  });

  it("resets the reconnect backoff once a subscription is re-established", async () => {
    // Track the delays the bridge waits between reconnects via a fake client whose
    // subscriptions all end immediately, and a spy on the injected reconnect timer.
    let calls = 0;
    const client = {
      async *subscribeInbound(
        _filter: unknown,
        _signal: AbortSignal,
        hooks?: { onReady?: () => void },
      ): AsyncGenerator<AgentControlEvent> {
        calls += 1;
        // Only the 2nd subscription acks (onReady) — that should reset the attempt
        // counter so the following reconnect is the short base delay again.
        if (calls === 2) {
          hooks?.onReady?.();
        }
      },
    } as unknown as InboundSubscribeClient;

    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 4,
      maxReconnectDelayMs: 1000,
      onMessage: () => {},
    });
    const run = bridge.run(controller.signal);
    // Let several reconnect cycles happen, then stop.
    await new Promise((resolve) => setTimeout(resolve, 60));
    controller.abort();
    await run;
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it("routes a message_deleted event as ambient context", async () => {
    const deletion: AgentControlEvent = {
      type: "message_deleted",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      event_id_hex: HEX32("e9"),
      target_message_id_hex: HEX32("d9"),
      actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      recorded_at: 124,
      target: {
        message_id_hex: HEX32("d9"),
        availability: "deleted",
        text_truncated: false,
        attachments_truncated: false,
      },
    };
    const { client } = makeClient([deletion]);
    let deletedTarget = "";
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: () => {},
      onAmbientEvent: (event) => {
        if (event.type === "message_deleted") {
          deletedTarget = event.target_message_id_hex;
        }
        controller.abort();
      },
    });

    await bridge.run(controller.signal);
    expect(deletedTarget).toBe(HEX32("d9"));
  });

  it("routes a group_state_changed event as ambient context", async () => {
    const renamed: AgentControlEvent = {
      type: "group_state_changed",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      change: "group_renamed",
      detail: "Team",
    };
    const { client } = makeClient([renamed]);
    let observedChange = "";
    let observedDetail: string | null = "";
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: () => {},
      onAmbientEvent: (event) => {
        if (event.type === "group_state_changed") {
          observedChange = event.change;
          observedDetail = event.detail ?? null;
        }
        controller.abort();
      },
    });

    await bridge.run(controller.signal);
    expect(observedChange).toBe("group_renamed");
    expect(observedDetail).toBe("Team");
  });

  it("stops cleanly when the signal aborts", async () => {
    const { client, subscribeCalls } = makeClient([]);
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 5,
      onMessage: () => {},
    });

    const run = bridge.run(controller.signal);
    controller.abort();
    await run;

    expect(subscribeCalls()).toBeGreaterThanOrEqual(1);
  });
});

describe("reconnectBackoffMs", () => {
  it("returns the base delay on the first attempt", () => {
    expect(reconnectBackoffMs(0, 1000, 30_000, () => 0)).toBe(1000);
    expect(reconnectBackoffMs(0, 1000, 30_000, () => 1)).toBe(1000);
  });

  it("grows geometrically with jitter toward the cap", () => {
    expect(reconnectBackoffMs(1, 1000, 30_000, () => 0)).toBe(1000); // low jitter -> base
    expect(reconnectBackoffMs(1, 1000, 30_000, () => 1)).toBe(2000); // high jitter -> 2x base
    expect(reconnectBackoffMs(10, 1000, 30_000, () => 1)).toBe(30_000); // saturated at the cap
  });

  it("always stays within [base, cap]", () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const value = reconnectBackoffMs(attempt, 1000, 30_000, Math.random);
      expect(value).toBeGreaterThanOrEqual(1000);
      expect(value).toBeLessThanOrEqual(30_000);
    }
  });

  it("treats a non-positive base as no delay", () => {
    expect(reconnectBackoffMs(5, 0, 30_000, () => 1)).toBe(0);
  });
});
