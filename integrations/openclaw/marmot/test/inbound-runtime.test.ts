import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  AgentControlEvent,
  AgentControlMediaRef,
  MarmotAgentControlClient,
} from "../src/client.js";
import {
  resetMarmotInboundAccountsForTests,
  startMarmotInbound,
  syncMarmotAllowlist,
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
    message: {
      message_id_hex: HEX32(idByte),
      sender: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      text: "hello agent",
      recorded_at: 123,
      media: [],
    },
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
  vi.useRealTimers();
  resetMarmotInboundAccountsForTests();
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
              ...inboundEvent("cc", "dd"),
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
              message: { ...inboundEvent("cc", "d1").message, text: "", media: [mediaA] },
              mentions_self: true,
              reply_to: {
                message_id_hex: HEX32("e1"),
                availability: "missing",
                text_truncated: false,
                attachments_truncated: false,
              },
            },
            {
              ...inboundEvent("cc", "d2"),
              message: {
                ...inboundEvent("cc", "d2").message,
                text: "",
                media: [{ ...mediaA, file_name: "a-duplicate.png" }, mediaB],
              },
            },
            {
              ...inboundEvent("cc", "d3"),
              message: { ...inboundEvent("cc", "d3").message, text: "what is this?", media: [] },
              mentions_self: false,
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

  it("bounds a debounced burst and emits only aggregate pressure details", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const warnings: string[] = [];
    const events = Array.from({ length: 33 }, (_, index) =>
      inboundEvent("cc", (index + 1).toString(16).padStart(2, "0")),
    );
    const stop = startMarmotInbound(
      {
        config: {
          channels: { marmot: { debounceMs: 25, profileNameOnboarding: false } },
        },
        logger: { info: () => undefined, warn: (message) => warnings.push(message) },
      },
      (message) => {
        dispatched.push(message);
      },
      { clientFactory: () => inboundStubClient(events) },
    );

    await waitFor(() => warnings.some((message) => message.includes("inbound debounce overloaded")));
    await waitFor(() => dispatched.length > 0);
    stop();

    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]?.text.split("\n")).toHaveLength(32);
    expect(warnings).toContain(
      "marmot: inbound debounce overloaded (reason=per_key_depth, active_keys=1, max_depth_per_key=32, max_tracked_keys=256)",
    );
    expect(warnings.join(" ")).not.toContain(events[32]!.message.message_id_hex);
  });

  it("buffers every mutation type and attaches them to the next triggering message", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, (message) => {
      dispatched.push(message);
    }, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "message_edited",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            event_id_hex: HEX32("e1"),
            target_message_id_hex: HEX32("dd"),
            actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
            replacement_text: "edited",
            recorded_at: 122,
            target: {
              message_id_hex: HEX32("dd"),
              availability: "available",
              text_excerpt: "before",
              text_truncated: false,
              attachments_truncated: false,
            },
          },
          {
            type: "reaction_added",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            event_id_hex: HEX32("e2"),
            target_message_id_hex: HEX32("dd"),
            actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
            emoji: "👍",
            recorded_at: 123,
            target: {
              message_id_hex: HEX32("dd"),
              availability: "available",
              text_excerpt: "before",
              text_truncated: false,
              attachments_truncated: false,
            },
          },
          {
            type: "reaction_removed",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            event_id_hex: HEX32("e3"),
            reaction_event_id_hex: HEX32("e2"),
            target_message_id_hex: HEX32("dd"),
            actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
            emoji: "👍",
            recorded_at: 124,
            target: {
              message_id_hex: HEX32("dd"),
              availability: "available",
              text_excerpt: "before",
              text_truncated: false,
              attachments_truncated: false,
            },
          },
          {
            type: "message_deleted",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            event_id_hex: HEX32("ee"),
            target_message_id_hex: HEX32("dd"),
            actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
            recorded_at: 125,
            target: {
              message_id_hex: HEX32("dd"),
              availability: "deleted",
              text_truncated: false,
              attachments_truncated: false,
            },
          },
          inboundEvent("cc", "ff"),
        ]),
    });

    await waitFor(() => dispatched.length > 0);
    stop();

    expect(dispatched[0]?.ambientContext?.map((event) => event.type)).toEqual([
      "message_edited",
      "reaction_added",
      "reaction_removed",
      "message_deleted",
    ]);
  });

  it("keeps ambient context when a non-triggering message is gated out", async () => {
    const attempted: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      (message) => {
        attempted.push(message);
        return attempted.length > 1;
      },
      {
        clientFactory: () =>
          inboundStubClient([
            {
              type: "reaction_added",
              account_id_hex: HEX32("aa"),
              group_id_hex: HEX32("cc"),
              event_id_hex: HEX32("e1"),
              target_message_id_hex: HEX32("dd"),
              actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
              emoji: "👍",
              recorded_at: 124,
              target: {
                message_id_hex: HEX32("dd"),
                availability: "available",
                text_excerpt: "target",
                text_truncated: false,
                attachments_truncated: false,
              },
            },
            inboundEvent("cc", "f1"),
            inboundEvent("cc", "f2"),
          ]),
      },
    );

    await waitFor(() => attempted.length === 2);
    stop();

    expect(attempted[0]?.ambientContext).toHaveLength(1);
    expect(attempted[1]?.ambientContext).toHaveLength(1);
    expect(attempted[1]?.ambientContext?.[0]).toMatchObject({
      type: "reaction_added",
      event_id_hex: HEX32("e1"),
    });
  });

  it("bounds pending ambient facts per account and group", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const mutations = Array.from({ length: 20 }, (_, index) => ({
      type: "message_edited" as const,
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      event_id_hex: index.toString(16).padStart(64, "0"),
      target_message_id_hex: HEX32("dd"),
      actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      replacement_text: `edit-${index}`,
      recorded_at: 124 + index,
      target: {
        message_id_hex: HEX32("dd"),
        availability: "available" as const,
        text_excerpt: "target",
        text_truncated: false,
        attachments_truncated: false,
      },
    }));
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message);
      },
      {
        clientFactory: () => inboundStubClient([...mutations, inboundEvent("cc", "ff")]),
      },
    );

    await waitFor(() => dispatched.length === 1);
    stop();

    expect(dispatched[0]?.ambientContext).toHaveLength(16);
    expect(dispatched[0]?.ambientContext?.[0]).toMatchObject({ replacement_text: "edit-4" });
    expect(dispatched[0]?.ambientContext?.at(-1)).toMatchObject({
      replacement_text: "edit-19",
    });
  });

  it("preserves ambient facts that arrive while a full batch is in flight", async () => {
    const groupIdHex = HEX32("cc");
    const oldMutations: AgentControlEvent[] = Array.from({ length: 16 }, (_, index) => ({
      type: "message_edited",
      account_id_hex: HEX32("aa"),
      group_id_hex: groupIdHex,
      event_id_hex: index.toString(16).padStart(64, "0"),
      target_message_id_hex: HEX32("dd"),
      actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      replacement_text: `old-${index}`,
      recorded_at: 124 + index,
      target: {
        message_id_hex: HEX32("dd"),
        availability: "available",
        text_excerpt: "target",
        text_truncated: false,
        attachments_truncated: false,
      },
    }));
    const lateMutation: AgentControlEvent = {
      type: "reaction_added",
      account_id_hex: HEX32("aa"),
      group_id_hex: groupIdHex,
      event_id_hex: HEX32("e9"),
      target_message_id_hex: HEX32("dd"),
      actor: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
      emoji: "🔥",
      recorded_at: 999,
      target: {
        message_id_hex: HEX32("dd"),
        availability: "available",
        text_excerpt: "target",
        text_truncated: false,
        attachments_truncated: false,
      },
    };
    let markTurnStarted: () => void = () => {};
    let releaseTurn: () => void = () => {};
    let markLateProcessed: () => void = () => {};
    const turnStarted = new Promise<void>((resolve) => {
      markTurnStarted = resolve;
    });
    const turnRelease = new Promise<void>((resolve) => {
      releaseTurn = resolve;
    });
    const lateProcessed = new Promise<void>((resolve) => {
      markLateProcessed = resolve;
    });
    const client = {
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
        for (const event of oldMutations) {
          yield event;
        }
        yield inboundEvent("cc", "f1");
        await turnStarted;
        yield lateMutation;
        // Reaching the next pull proves the bridge processed lateMutation.
        markLateProcessed();
        await turnRelease;
        yield inboundEvent("cc", "f2");
      },
    } as unknown as MarmotAgentControlClient;
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      async (message) => {
        dispatched.push(message);
        if (dispatched.length === 1) {
          markTurnStarted();
          await turnRelease;
        }
        return true;
      },
      { clientFactory: () => client },
    );

    await turnStarted;
    await lateProcessed;
    releaseTurn();
    await waitFor(() => dispatched.length === 2);
    stop();

    expect(dispatched[0]?.ambientContext).toHaveLength(16);
    expect(dispatched[1]?.ambientContext).toEqual([lateMutation]);
  });

  it("bounds the number of groups holding pending ambient context", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const groupIds = Array.from({ length: 257 }, (_, index) =>
      index.toString(16).padStart(64, "0"),
    );
    const mutations = groupIds.map((groupId, index) => ({
      type: "group_state_changed" as const,
      account_id_hex: HEX32("aa"),
      group_id_hex: groupId,
      change: "group_renamed",
      detail: `group-${index}`,
    }));
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
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
            ...mutations,
            { ...inboundEvent("cc", "f1"), group_id_hex: groupIds[0]! },
            { ...inboundEvent("cc", "f2"), group_id_hex: groupIds.at(-1)! },
          ]),
      },
    );

    await waitFor(() => dispatched.length === 2);
    stop();

    const oldest = dispatched.find((message) => message.groupIdHex === groupIds[0]);
    const newest = dispatched.find((message) => message.groupIdHex === groupIds.at(-1));
    expect(oldest?.ambientContext).toHaveLength(0);
    expect(newest?.ambientContext).toHaveLength(1);
  });

  it("buffers group state as structured next-turn context", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, (message) => {
      dispatched.push(message);
    }, {
      clientFactory: () =>
        inboundStubClient([
          {
            type: "group_state_changed",
            account_id_hex: HEX32("aa"),
            group_id_hex: HEX32("cc"),
            change: "group_renamed",
            detail: "Project Marmot",
          },
          inboundEvent("cc", "ff"),
        ]),
    });

    await waitFor(() => dispatched.length > 0);
    stop();

    expect(dispatched[0]?.ambientContext?.[0]).toMatchObject({
      type: "group_state_changed",
      change: "group_renamed",
      detail: "Project Marmot",
    });
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

  it("dispatches debounced distinct groups concurrently and keeps per-group FIFO order", async () => {
    vi.useFakeTimers();
    const a1 = HEX32("d1");
    const a2 = HEX32("d2");
    const b1 = HEX32("d3");
    const started: string[] = [];
    const gates = new Map<string, () => void>();
    const gate = (id: string) => new Promise<void>((resolve) => gates.set(id, resolve));

    const api: InboundPluginApi = {
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(
      api,
      async (message) => {
        started.push(message.messageIdHex);
        await gate(message.messageIdHex);
      },
      {
        clientFactory: () => {
          const secondGroupATurn = inboundEvent("ca", "d2");
          secondGroupATurn.message.sender.account_id_hex = HEX32("bc");
          return inboundStubClient([
            inboundEvent("ca", "d1"), // group A, sender 1
            secondGroupATurn, // group A, sender 2: separate debounce key, FIFO turn
            inboundEvent("cb", "d3"), // group B (independent)
          ]);
        },
      },
    );

    await vi.advanceTimersByTimeAsync(10);
    // A's first and B's first run concurrently; A's second remains FIFO behind A's first.
    expect(started).toContain(a1);
    expect(started).toContain(b1);
    expect(started).not.toContain(a2);

    gates.get(a1)?.();
    await vi.advanceTimersByTimeAsync(0);
    expect(started).toContain(a2);

    gates.get(a2)?.();
    gates.get(b1)?.();
    await vi.advanceTimersByTimeAsync(0);
    stop();
  });

  it("cancels startup-raced debounce work on external abort and accepts replay", async () => {
    vi.useFakeTimers();
    const event = inboundEvent("cc", "d4");
    const dispatched: MarmotInboundMessage[] = [];
    const config = {
      channels: { marmot: { debounceMs: 25, profileNameOnboarding: false } },
    };
    const externalController = new AbortController();
    let releaseAccountList!: () => void;
    const accountListGate = new Promise<void>((resolve) => {
      releaseAccountList = resolve;
    });
    const startupRacedClient = {
      async accountList() {
        await accountListGate;
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
        yield event;
      },
    } as unknown as MarmotAgentControlClient;

    const firstStop = startMarmotInbound(
      { config, logger: noopLogger },
      (message) => {
        dispatched.push(message);
      },
      {
        signal: externalController.signal,
        clientFactory: () => startupRacedClient,
      },
    );

    externalController.abort();
    releaseAccountList();
    await vi.advanceTimersByTimeAsync(25);
    expect(dispatched).toHaveLength(0);

    const secondStop = startMarmotInbound(
      { config, logger: noopLogger },
      (message) => {
        dispatched.push(message);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await vi.advanceTimersByTimeAsync(25);
    expect(dispatched.map((message) => message.messageIdHex)).toEqual([
      event.message.message_id_hex,
    ]);

    firstStop();
    secondStop();
  });

  it("cancels a buffered debounce on stop and accepts the replay after restart", async () => {
    vi.useFakeTimers();
    const event = inboundEvent("cc", "d4");
    const dispatched: MarmotInboundMessage[] = [];
    const config = {
      channels: { marmot: { debounceMs: 25, profileNameOnboarding: false } },
    };
    const firstStop = startMarmotInbound(
      { config, logger: noopLogger },
      (message) => {
        dispatched.push(message);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );

    await vi.advanceTimersByTimeAsync(0);
    firstStop();
    await vi.advanceTimersByTimeAsync(25);
    expect(dispatched).toHaveLength(0);

    const secondStop = startMarmotInbound(
      { config, logger: noopLogger },
      (message) => {
        dispatched.push(message);
      },
      { clientFactory: () => inboundStubClient([event]) },
    );
    await vi.advanceTimersByTimeAsync(25);
    expect(dispatched.map((message) => message.messageIdHex)).toEqual([
      event.message.message_id_hex,
    ]);
    secondStop();
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

  it("warns when a welcomer revocation cannot be applied", async () => {
    const stale = HEX32("99");
    const warnings: string[] = [];
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
          welcomer_account_ids_hex: [stale],
        };
      },
      async allowlistAdd() {
        return { type: "ack" };
      },
      async allowlistRemove() {
        throw new Error("allowlist_remove failed");
      },
    } as unknown as MarmotAgentControlClient;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };

    await syncMarmotAllowlist(api, { clientFactory: () => client });

    expect(warnings.some((message) => message.includes("revocation failed"))).toBe(true);
    expect(warnings.join(" ")).not.toContain(stale);
  });
});
