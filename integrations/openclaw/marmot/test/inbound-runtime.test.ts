import { afterEach, describe, expect, it } from "vitest";

import type { AgentControlEvent, MarmotAgentControlClient } from "../src/client.js";
import {
  startMarmotInbound,
  syncMarmotAllowlist,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import {
  marmotInboundRuntimeSnapshot,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const HEX32 = (b: string) => b.repeat(32);
const noopLogger = { info: () => {}, warn: () => {} };

function inboundStubClient(events: AgentControlEvent[]): MarmotAgentControlClient {
  return {
    async accountList() {
      return {
        type: "account_list",
        accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
      };
    },
    async *subscribeInbound(
      _filter?: unknown,
      _signal?: AbortSignal,
      hooks?: { onReady?: () => void },
    ): AsyncGenerator<AgentControlEvent> {
      hooks?.onReady?.();
      for (const event of events) {
        yield event;
      }
    },
  } as unknown as MarmotAgentControlClient;
}

function inboundEvent(groupByte: string, idByte: string): AgentControlEvent {
  return {
    type: "inbound_message",
    account_id_hex: HEX32("aa"),
    group_id_hex: HEX32(groupByte),
    message_id_hex: HEX32(idByte),
    sender_account_id_hex: HEX32("bb"),
    text: "hello agent",
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("waitFor timed out");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
});

describe("startMarmotInbound", () => {
  it("resolves the agent account and dispatches mapped inbound messages", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    let resolveFirst: () => void = () => {};
    const firstDispatch = new Promise<void>((resolve) => {
      resolveFirst = resolve;
    });

    // Disable profile onboarding so this exercises the dispatch path directly
    // (onboarding is on by default and would intercept the first message).
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message);
        resolveFirst();
      },
      {
        clientFactory: () =>
          inboundStubClient([
            {
              type: "inbound_message",
              account_id_hex: HEX32("aa"),
              group_id_hex: HEX32("cc"),
              message_id_hex: HEX32("dd"),
              sender_account_id_hex: HEX32("bb"),
              text: "hello agent",
            },
          ]),
      },
    );

    await firstDispatch;
    const active = marmotInboundRuntimeSnapshot("default");
    expect(active.running).toBe(true);
    expect(active.connected).toBe(true);
    expect(active.lastStartAt).toEqual(expect.any(Number));
    expect(active.lastInboundAt).toEqual(expect.any(Number));

    stop();

    const stopped = marmotInboundRuntimeSnapshot("default");
    expect(stopped.running).toBe(false);
    expect(stopped.connected).toBe(false);
    expect(stopped.lastStopAt).toEqual(expect.any(Number));

    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("dd"),
      text: "hello agent",
    });
  });

  it("surfaces a message deletion to the ambient surfacer with a stable contextKey", async () => {
    const surfaced: { groupIdHex: string; text: string; contextKey?: string }[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "message_deleted",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            target_message_id_hex: HEX32("dd"),
            sender_account_id_hex: HEX32("bb"),
          },
        ]),
      surfaceAmbientEvent: (event) => {
        surfaced.push(event);
      },
    });

    await waitFor(() => surfaced.length > 0);
    stop();

    expect(surfaced[0]).toMatchObject({
      groupIdHex: HEX32("cc"),
      text: "A message was deleted.",
      contextKey: `marmot:message_deleted:${HEX32("cc")}:${HEX32("dd")}`,
    });
  });

  it("surfaces a group rename with the new name and a change-scoped contextKey", async () => {
    const surfaced: { groupIdHex: string; text: string; contextKey?: string }[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "group_state_changed",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            change: "group_renamed",
            detail: "Project Marmot",
          },
        ]),
      surfaceAmbientEvent: (event) => {
        surfaced.push(event);
      },
    });

    await waitFor(() => surfaced.length > 0);
    stop();

    expect(surfaced[0]).toMatchObject({
      groupIdHex: HEX32("cc"),
      text: 'The group was renamed to "Project Marmot".',
      contextKey: `marmot:group_state_changed:${HEX32("cc")}:group_renamed`,
    });
  });

  it("surfaces a membership change without any member detail", async () => {
    const surfaced: { text: string }[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "group_state_changed",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            change: "member_added",
            detail: null,
          },
        ]),
      surfaceAmbientEvent: (event) => {
        surfaced.push(event);
      },
    });

    await waitFor(() => surfaced.length > 0);
    stop();

    expect(surfaced[0]?.text).toBe("A member was added to the group.");
  });

  it("invalidates the dispatcher's group-activation cache on a group_state_changed event", async () => {
    const invalidated: { accountIdHex: string; groupIdHex: string }[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "group_state_changed",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            change: "member_removed",
            detail: null,
          },
        ]),
      invalidateGroupActivation: (accountIdHex, groupIdHex) => {
        invalidated.push({ accountIdHex, groupIdHex });
      },
    });

    await waitFor(() => invalidated.length > 0);
    stop();

    expect(invalidated[0]).toEqual({ accountIdHex: HEX32("aa"), groupIdHex: HEX32("cc") });
  });

  it("clears the whole group-activation cache on an inbound resync", async () => {
    let cleared = 0;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "resync_required",
            account_id_hex: HEX32("aa"),
            group_id_hex: null,
            dropped_events: 3,
          },
        ]),
      clearGroupActivationCache: () => {
        cleared += 1;
      },
    });

    await waitFor(() => cleared > 0);
    stop();

    expect(cleared).toBe(1);
  });

  it("dispatches distinct groups concurrently and keeps per-group FIFO order", async () => {
    const a1 = HEX32("d1");
    const a2 = HEX32("d2");
    const b1 = HEX32("d3");
    const started: string[] = [];
    const gates = new Map<string, () => void>();
    const gate = (id: string) => new Promise<void>((resolve) => gates.set(id, resolve));

    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      async (message) => {
        started.push(message.messageIdHex);
        await gate(message.messageIdHex);
      },
      {
        clientFactory: () =>
          inboundStubClient([
            inboundEvent("ca", "d1"), // group A, message 1
            inboundEvent("ca", "d2"), // group A, message 2 (FIFO behind a1)
            inboundEvent("cb", "d3"), // group B, message 1 (independent)
          ]),
      },
    );

    // A's first and B's first run concurrently; A's second must wait behind A's first.
    await waitFor(() => started.includes(a1) && started.includes(b1));
    expect(started).not.toContain(a2);

    gates.get(a1)?.(); // release A's first -> A's second may start
    await waitFor(() => started.includes(a2));

    gates.get(a2)?.();
    gates.get(b1)?.();
    stop();
  });
});

describe("syncMarmotAllowlist", () => {
  function allowlistStubClient(current: string[]): {
    client: MarmotAgentControlClient;
    added: string[];
    removed: string[];
  } {
    const added: string[] = [];
    const removed: string[] = [];
    const client = {
      async accountList() {
        return {
          type: "account_list",
          accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
        };
      },
      async allowlistList() {
        return {
          type: "allowlist",
          account_id_hex: HEX32("aa"),
          welcomer_account_ids_hex: current,
        };
      },
      async allowlistAdd(_account: string, id: string) {
        added.push(id);
        return { type: "ack" };
      },
      async allowlistRemove(_account: string, id: string) {
        removed.push(id);
        return { type: "ack" };
      },
    } as unknown as MarmotAgentControlClient;
    return { client, added, removed };
  }

  it("mirrors configured dm.allowFrom into the dm-agent allowlist", async () => {
    const { client, added } = allowlistStubClient([]);
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: noopLogger,
    };
    await syncMarmotAllowlist(api, { clientFactory: () => client });
    expect(added).toEqual([HEX32("11")]);
  });

  it("is a no-op (no client used) when no allowFrom is configured", async () => {
    let used = false;
    const api: InboundPluginApi = { config: { channels: { marmot: {} } }, logger: noopLogger };
    await syncMarmotAllowlist(api, {
      clientFactory: () => {
        used = true;
        return {} as unknown as MarmotAgentControlClient;
      },
    });
    expect(used).toBe(false);
  });
});
