import { afterEach, describe, expect, it } from "vitest";

import type {
  AgentControlEvent,
  AgentControlMediaRef,
  MarmotAgentControlClient,
} from "../src/client.js";
import {
  MarmotDispatchAmbiguousDeliveryError,
  MarmotDispatchDeliveryFailedError,
  MarmotDispatchNotReadyError,
} from "../src/dispatch-errors.js";
import {
  startMarmotInbound,
  syncMarmotAllowlist,
  resetMarmotInboundAccountsForTests,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import {
  marmotInboundRuntimeSnapshot,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

type InboundMessageEvent = Extract<AgentControlEvent, { type: "inbound_message" }>;

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

function inboundEvent(groupByte: string, idByte: string): InboundMessageEvent {
  return {
    type: "inbound_message",
    account_id_hex: HEX32("aa"),
    group_id_hex: HEX32(groupByte),
    message_id_hex: HEX32(idByte),
    sender_account_id_hex: HEX32("bb"),
    text: "hello agent",
  };
}

function mediaRef(ciphertextSha256: string, fileName: string): AgentControlMediaRef {
  return {
    media_type: "image/png",
    file_name: fileName,
    ciphertext_sha256: ciphertextSha256,
    plaintext_sha256: HEX32("ee"),
    nonce_hex: "00".repeat(12),
    version: "v1",
    source_epoch: 7,
    locators: [{ kind: "nip94", value: `nostr:${ciphertextSha256}` }],
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
  resetMarmotInboundAccountsForTests();
});

describe("startMarmotInbound", () => {
  it("does not poison the account guard when control-client construction fails", async () => {
    const logs: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: { info: (message) => logs.push(message), warn: (message) => logs.push(message) },
    };

    expect(() =>
      startMarmotInbound(api, () => {}, {
        clientFactory: () => {
          throw new Error("client construction failed");
        },
      }),
    ).toThrow("client construction failed");

    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () => inboundStubClient([]),
    });
    await waitFor(() => logs.some((message) => message.includes("subscription established")));
    stop();
    expect(logs).not.toContain("marmot: inbound subscription already active; ignoring duplicate start");
  });

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

  it("coalesces debounced bursts without dropping media, mentions, or reply context", async () => {
    const mediaA = mediaRef(HEX32("a1"), "a.png");
    const mediaB = mediaRef(HEX32("b2"), "b.png");
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message);
      },
      {
        clientFactory: () =>
          inboundStubClient([
            {
              ...inboundEvent("cc", "d1"),
              text: "",
              mentions_self: true,
              reply_to_message_id_hex: HEX32("e1"),
              media: [mediaA],
            },
            {
              ...inboundEvent("cc", "d2"),
              text: "",
              media: [{ ...mediaA, file_name: "a-duplicate.png" }, mediaB],
            },
            {
              ...inboundEvent("cc", "d3"),
              text: "what is this?",
              mentions_self: false,
              reply_to_message_id_hex: null,
              media: [],
            },
          ]),
      },
    );

    await waitFor(() => dispatched.length > 0);
    stop();

    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({
      groupIdHex: HEX32("cc"),
      messageIdHex: HEX32("d3"),
      text: "what is this?",
      mentionsSelf: true,
      replyToMessageIdHex: HEX32("e1"),
    });
    expect(dispatched[0]?.media).toEqual([mediaA, mediaB]);
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

  it("surfaces a disappearing-message timer change", async () => {
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
            change: "disappearing_timer_changed",
          },
        ]),
      surfaceAmbientEvent: (event) => {
        surfaced.push(event);
      },
    });

    await waitFor(() => surfaced.length > 0);
    stop();

    expect(surfaced[0]?.text).toBe("The disappearing-message timer was changed.");
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

  it("mirrors configured dm.allowFrom into the wn-agent allowlist", async () => {
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

  it("syncs the requested multi-account slice, not only default", async () => {
    const synced: string[] = [];
    const client = {
      async accountList() {
        return {
          type: "account_list",
          accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
        };
      },
      async allowlistList() {
        return { type: "allowlist", account_id_hex: HEX32("aa"), welcomer_account_ids_hex: [] };
      },
      async allowlistAdd(_account: string, id: string) {
        synced.push(id);
        return { type: "ack" };
      },
      async allowlistRemove() {
        return { type: "ack" };
      },
    } as unknown as MarmotAgentControlClient;
    const api: InboundPluginApi = {
      config: {
        channels: {
          marmot: {
            accounts: {
              alice: { socketPath: "/a.sock", dm: { allowFrom: [HEX32("11")] } },
              bob: { socketPath: "/b.sock", dm: { allowFrom: [HEX32("22")] } },
            },
          },
        },
      },
      logger: noopLogger,
    };
    await syncMarmotAllowlist(api, { clientFactory: () => client, channelAccountId: "bob" });
    expect(synced).toEqual([HEX32("22")]);
  });
});

describe("startMarmotInbound readiness redelivery", () => {
  it("retries readiness timeout inside the per-group queue and dispatches one turn", async () => {
    const messageId = HEX32("f2");
    const event = inboundEvent("cc", "f2");
    event.message_id_hex = messageId;
    let attempts = 0;
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stop = startMarmotInbound(
      api,
      async (message) => {
        attempts += 1;
        if (attempts < 3) {
          throw new MarmotDispatchNotReadyError("timeout");
        }
        dispatched.push(message.messageIdHex);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await waitFor(() => dispatched.length === 1);
    stop();
    expect(dispatched).toEqual([messageId]);
    expect(attempts).toBe(3);
  });

  it("fails fast on non-retryable readiness without consuming retry slots", async () => {
    const messageId = HEX32("f4");
    const event = inboundEvent("cc", "f4");
    event.message_id_hex = messageId;
    let attempts = 0;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stop = startMarmotInbound(
      api,
      async () => {
        attempts += 1;
        throw new MarmotDispatchNotReadyError("non_retryable");
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    stop();
    expect(attempts).toBe(1);
  });

  it("clears dedupe on exhausted readiness so stop/start replay can dispatch once", async () => {
    const messageId = HEX32("f3");
    const event = inboundEvent("cc", "f3");
    event.message_id_hex = messageId;
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stopFirst = startMarmotInbound(
      api,
      async () => {
        throw new MarmotDispatchNotReadyError("non_retryable");
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    stopFirst();

    const stopSecond = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message.messageIdHex);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await waitFor(() => dispatched.length === 1);
    stopSecond();
    expect(dispatched).toEqual([messageId]);
  });

  it("keeps successful inbound messages deduped after readiness exhaustion on another id", async () => {
    const successId = HEX32("a1");
    const failedId = HEX32("a2");
    const successEvent = inboundEvent("cc", "a1");
    successEvent.message_id_hex = successId;
    const failedEvent = inboundEvent("cc", "a2");
    failedEvent.message_id_hex = failedId;
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stop = startMarmotInbound(
      api,
      async (message) => {
        dispatched.push(message.messageIdHex);
        if (message.messageIdHex === failedId) {
          throw new MarmotDispatchNotReadyError("non_retryable");
        }
      },
      { clientFactory: () => inboundStubClient([successEvent, failedEvent, successEvent]) },
    );
    await waitFor(() => dispatched.includes(successId) && dispatched.includes(failedId));
    await new Promise((resolve) => setTimeout(resolve, 100));
    stop();
    expect(dispatched.filter((id) => id === successId)).toEqual([successId]);
  });

  it("rolls back dedupe for every coalesced debounced id after readiness exhaustion", async () => {
    const firstId = HEX32("b1");
    const secondId = HEX32("b2");
    const firstEvent = inboundEvent("cc", "b1");
    firstEvent.message_id_hex = firstId;
    firstEvent.text = "part one";
    const secondEvent = inboundEvent("cc", "b2");
    secondEvent.message_id_hex = secondId;
    secondEvent.text = "part two";
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stopFirst = startMarmotInbound(
      api,
      async () => {
        throw new MarmotDispatchNotReadyError("non_retryable");
      },
      { clientFactory: () => inboundStubClient([firstEvent, secondEvent]) },
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    stopFirst();

    const stopSecond = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message.messageIdHex);
      },
      { clientFactory: () => inboundStubClient([firstEvent, secondEvent]) },
    );
    await waitFor(() => dispatched.length === 1);
    stopSecond();
    expect(dispatched).toEqual([secondId]);
  });

  it.each([
    ["ambiguous delivery", () => new MarmotDispatchAmbiguousDeliveryError()],
    ["terminal delivery failure", () => new MarmotDispatchDeliveryFailedError()],
  ])("rolls back every coalesced id after %s so reconnect can replay", async (_label, failure) => {
    const firstId = HEX32("c1");
    const secondId = HEX32("c2");
    const firstEvent = inboundEvent("cc", "c1");
    firstEvent.message_id_hex = firstId;
    firstEvent.text = "part one";
    const secondEvent = inboundEvent("cc", "c2");
    secondEvent.message_id_hex = secondId;
    secondEvent.text = "part two";
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false } } },
      logger: { info: () => {}, warn: (message) => warnings.push(message) },
    };

    const stopFirst = startMarmotInbound(
      api,
      async () => {
        throw failure();
      },
      { clientFactory: () => inboundStubClient([firstEvent, secondEvent]) },
    );
    await waitFor(() => warnings.some((message) => message.includes("dispatch task failed")));
    stopFirst();

    const replayed: MarmotInboundMessage[] = [];
    const stopSecond = startMarmotInbound(
      api,
      (message) => {
        replayed.push(message);
      },
      { clientFactory: () => inboundStubClient([firstEvent, secondEvent]) },
    );
    await waitFor(() => replayed.length === 1);
    stopSecond();

    expect(replayed[0]?.messageIdHex).toBe(secondId);
    expect(replayed[0]?.coalescedMessageIdsHex).toEqual([firstId, secondId]);
  });

  it("stops readiness retries on abort and rolls back dedupe without dispatching again", async () => {
    const messageId = HEX32("f5");
    const event = inboundEvent("cc", "f5");
    event.message_id_hex = messageId;
    let attempts = 0;
    const controller = new AbortController();
    let releaseAttempt: (() => void) | undefined;
    const attemptGate = new Promise<void>((resolve) => {
      releaseAttempt = resolve;
    });
    let notifyAttemptStarted: (() => void) | undefined;
    const attemptStarted = new Promise<void>((resolve) => {
      notifyAttemptStarted = resolve;
    });
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stop = startMarmotInbound(
      api,
      async () => {
        attempts += 1;
        notifyAttemptStarted?.();
        await attemptGate;
        throw new MarmotDispatchNotReadyError("timeout");
      },
      { clientFactory: () => inboundStubClient([event]), signal: controller.signal },
    );
    await attemptStarted;
    controller.abort();
    releaseAttempt?.();
    await new Promise((resolve) => setImmediate(resolve));
    stop();

    expect(attempts).toBe(1);

    let replayAttempts = 0;
    const stopReplay = startMarmotInbound(
      api,
      async (message) => {
        replayAttempts += 1;
        expect(message.messageIdHex).toBe(messageId);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await waitFor(() => replayAttempts === 1);
    stopReplay();
  });
});

describe("startMarmotInbound queue shedding", () => {
  it("rolls back dedupe when enqueue rejects due to per-group depth", async () => {
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const groupId = HEX32("cc");
    const msg1 = inboundEvent("cc", "01");
    const msg2 = inboundEvent("cc", "02");
    const msg3 = inboundEvent("cc", "03");
    msg1.group_id_hex = groupId;
    msg2.group_id_hex = groupId;
    msg3.group_id_hex = groupId;
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };

    const stopFirst = startMarmotInbound(
      api,
      async (message) => {
        dispatched.push(message.messageIdHex);
        if (message.messageIdHex === msg1.message_id_hex) {
          await firstGate;
        }
      },
      {
        clientFactory: () => inboundStubClient([msg1, msg2, msg3]),
        inboundQueueMaxDepth: 2,
      },
    );

    await new Promise((resolve) => setTimeout(resolve, 50));
    releaseFirst?.();
    await waitFor(() => dispatched.length === 2);
    stopFirst();

    const stopSecond = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message.messageIdHex);
      },
      { clientFactory: () => inboundStubClient([msg3]) },
    );
    await waitFor(() => dispatched.filter((id) => id === msg3.message_id_hex).length === 1);
    stopSecond();

    expect(dispatched.filter((id) => id === msg3.message_id_hex)).toEqual([msg3.message_id_hex]);
  });
});

describe("startMarmotInbound subscription restart dedupe", () => {
  it("does not dispatch the same inbound message id twice after stop/start in one process", async () => {
    const messageId = HEX32("f1");
    const event = inboundEvent("cc", "f1");
    event.message_id_hex = messageId;
    let generation = 0;
    const dispatched: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stopFirst = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message.messageIdHex);
      },
      {
        clientFactory: () => {
          generation += 1;
          return inboundStubClient(generation === 1 ? [event] : [event]);
        },
      },
    );
    await waitFor(() => dispatched.length === 1);
    stopFirst();
    const stopSecond = startMarmotInbound(api, (message) => {
      dispatched.push(message.messageIdHex);
    }, {
      clientFactory: () => inboundStubClient([event]),
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    stopSecond();
    expect(dispatched).toEqual([messageId]);
  });
});
