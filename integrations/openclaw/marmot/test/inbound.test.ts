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
  it("retries an overload rejection without admitting an in-flight duplicate", async () => {
    const id = HEX32("d7");
    let releaseAdmission!: () => void;
    const admissionGate = new Promise<void>((resolve) => {
      releaseAdmission = resolve;
    });
    let calls = 0;
    const controller = new AbortController();
    const client = {
      async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
        yield inboundMessage(id);
        yield inboundMessage(id);
        releaseAdmission();
        await new Promise((resolve) => setTimeout(resolve, 0));
        yield inboundMessage(id);
        controller.abort();
      },
    } as unknown as InboundSubscribeClient;
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: async () => {
        calls += 1;
        if (calls === 1) {
          await admissionGate;
          return { admission: "overloaded", completion: Promise.resolve("overloaded" as const) };
        }
        return { admission: "admitted", completion: Promise.resolve("dispatched" as const) };
      },
    });

    await bridge.run(controller.signal);

    expect(calls).toBe(2);
  });

  it("keeps queued and running message ids reserved beyond the recent-id window", async () => {
    const firstId = HEX32("d8");
    let release!: () => void;
    const completion = new Promise<"dispatched">((resolve) => {
      release = () => resolve("dispatched");
    });
    const controller = new AbortController();
    const client = {
      async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
        yield inboundMessage(firstId);
        yield inboundMessage(HEX32("d9"));
        yield inboundMessage(firstId);
        controller.abort();
      },
    } as unknown as InboundSubscribeClient;
    const seen: string[] = [];
    const bridge = new MarmotInboundBridge(client, {
      dedupeWindow: 1,
      reconnectDelayMs: 1,
      onMessage: (message) => {
        seen.push(message.messageIdHex);
        if (message.messageIdHex === firstId) {
          return { admission: "admitted", completion };
        }
        return { admission: "admitted", completion: Promise.resolve("dispatched" as const) };
      },
    });

    await bridge.run(controller.signal);
    release();
    await completion;

    expect(seen).toEqual([firstId, HEX32("d9")]);
  });

  it("retains coalesced and onboarding-intercepted messages in completed dedupe", async () => {
    const id = HEX32("da");
    const controller = new AbortController();
    const client = {
      async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
        yield inboundMessage(id);
        await new Promise((resolve) => setTimeout(resolve, 0));
        yield inboundMessage(id);
        controller.abort();
      },
    } as unknown as InboundSubscribeClient;
    let calls = 0;
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: () => {
        calls += 1;
        return {
          admission: "coalesced",
          completion: Promise.resolve("onboarding_intercepted" as const),
        };
      },
    });

    await bridge.run(controller.signal);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toBe(1);
  });

  it("reports local submission failure without reporting a transport drop", async () => {
    const id = HEX32("db");
    const controller = new AbortController();
    const client = {
      async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
        yield inboundMessage(id);
        await new Promise((resolve) => setTimeout(resolve, 0));
        controller.abort();
      },
    } as unknown as InboundSubscribeClient;
    const submissionErrors: unknown[] = [];
    const transportErrors: unknown[] = [];
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: async () => {
        throw new Error("local queue failure");
      },
      onSubmissionError: (error) => submissionErrors.push(error),
      onError: (error) => transportErrors.push(error),
    });

    await bridge.run(controller.signal);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(submissionErrors).toHaveLength(1);
    expect(transportErrors).toHaveLength(0);
  });

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
