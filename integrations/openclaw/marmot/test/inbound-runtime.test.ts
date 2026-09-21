import { getEventListeners } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  AgentControlEvent,
  AgentControlMediaRef,
  MarmotAgentControlClient,
} from "../src/client.js";
import {
  createMarmotInboundDispatcher,
  type MarmotDispatchClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";
import {
  resetMarmotInboundAccountsForTests,
  startMarmotInbound,
  syncMarmotAllowlist,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import { testAllowlistAuthorizer } from "./sender-policy-fixtures.js";
import {
  beginMarmotAccountLifecycle,
  markMarmotAllowlistSyncResult,
  marmotInboundRuntimeSnapshot,
  MARMOT_ALLOWLIST_SYNC_FAILED,
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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

  it("denies an unlisted sender before onboarding or dispatch", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const logs: string[] = [];
    const unauthorized = inboundEvent("cc", "d1");
    unauthorized.message.sender.account_id_hex = HEX32("99");
    const api: InboundPluginApi = {
      config: {
        channels: {
          marmot: {
            profileNameOnboarding: true,
            senderPolicy: { allowedUsers: [HEX32("bb")] },
          },
        },
      },
      logger: {
        info: (message) => logs.push(message),
        warn: (message) => logs.push(message),
      },
    };
    const stop = startMarmotInbound(api, (message) => {
      dispatched.push(message);
    }, {
      clientFactory: () => inboundStubClient([unauthorized]),
    });
    await waitFor(() => logs.some((line) => line.includes("reason=sender_not_allowed")));
    expect(dispatched).toEqual([]);
    expect(logs.join("\n")).not.toContain(HEX32("99"));
    expect(logs.join("\n")).not.toContain(HEX32("bb"));
    stop();
  });

  it("keeps composed policy degradation after subscription acknowledgement", async () => {
    beginMarmotAccountLifecycle("default");
    markMarmotAllowlistSyncResult("default", { state: "failed", reason: "unverified" });
    const patches: Array<Record<string, unknown>> = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => undefined, {
      clientFactory: () => inboundStubClient([]),
      statusSink: (patch) => {
        patches.push(patch);
      },
    });
    await waitFor(() => patches.some((patch) => patch.lastError === MARMOT_ALLOWLIST_SYNC_FAILED));
    const ready = patches.find((patch) => patch.lastError === MARMOT_ALLOWLIST_SYNC_FAILED && patch.running === true);
    expect(ready).toMatchObject({
      connected: false,
      lastError: MARMOT_ALLOWLIST_SYNC_FAILED,
    });
    expect(JSON.stringify(patches)).not.toContain(HEX32("11"));
    stop();
  });

  it("signals setup failure so the gateway can retry without a duplicate subscription", async () => {
    const failures: number[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };
    const first = startMarmotInbound(api, () => undefined, {
      clientFactory: () => {
        throw new Error("secret socket detail");
      },
      onSetupFailed: () => {
        failures.push(1);
      },
    });
    expect(failures).toEqual([1]);
    expect(marmotInboundRuntimeSnapshot("default")).toMatchObject({
      running: false,
      connected: false,
    });
    // Failed attempts release their reservation without requiring stop().
    first();
    const dispatched: MarmotInboundMessage[] = [];
    const second = startMarmotInbound(
      api,
      (message) => {
        dispatched.push(message);
      },
      {
        clientFactory: () => inboundStubClient([inboundEvent("cc", "dd")]),
      },
    );
    await waitFor(() => dispatched.length === 1);
    expect(dispatched).toHaveLength(1);
    second();
  });

  it("publishes a privacy-safe inbound error when synchronous account resolution fails", () => {
    const patches: Array<Record<string, unknown>> = [];
    const warnings: string[] = [];
    let setupFailures = 0;
    const previousToken = process.env.MARMOT_AGENT_AUTH_TOKEN;
    const previousTokenFile = process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
    delete process.env.MARMOT_AGENT_AUTH_TOKEN;
    delete process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
    try {
      const stop = startMarmotInbound(
        {
          config: {
            channels: {
              marmot: { dm: { allowFrom: [] }, authTokenFile: "/secret/token-file" },
            },
          },
          logger: {
            info: () => {},
            warn: (message: string) => warnings.push(message),
          },
        },
        () => undefined,
        {
          statusSink: (patch) => {
            patches.push(patch);
          },
          onSetupFailed: () => {
            setupFailures += 1;
          },
        },
      );
      expect(setupFailures).toBe(1);
      expect(patches.at(-1)).toMatchObject({
        running: false,
        connected: false,
        lastError: "could not resolve agent account",
      });
      expect(patches.at(-1)?.lastError).not.toBe(MARMOT_ALLOWLIST_SYNC_FAILED);
      expect(JSON.stringify({ patches, warnings })).not.toContain("/secret/token-file");
      stop();
    } finally {
      if (previousToken === undefined) {
        delete process.env.MARMOT_AGENT_AUTH_TOKEN;
      } else {
        process.env.MARMOT_AGENT_AUTH_TOKEN = previousToken;
      }
      if (previousTokenFile === undefined) {
        delete process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
      } else {
        process.env.MARMOT_AGENT_AUTH_TOKEN_FILE = previousTokenFile;
      }
    }
  });

  it("ignores a late accountList failure after a replacement is acknowledged", async () => {
    let rejectOld!: (error: Error) => void;
    const oldAccountList = new Promise<never>((_resolve, reject) => {
      rejectOld = reject;
    });
    const hostPatches: Array<Record<string, unknown>> = [];
    const oldStop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
            async accountList() {
              return oldAccountList;
            },
            async *subscribeInbound() {
              throw new Error("old generation must not subscribe");
            },
          }) as unknown as MarmotAgentControlClient,
        statusSink: (patch) => {
          hostPatches.push({ ...patch, source: "old" });
        },
      },
    );
    oldStop();
    await Promise.resolve();

    const replacementHost: Array<Record<string, unknown>> = [];
    let replacementSubscribes = 0;
    const replacementStop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
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
            ) {
              replacementSubscribes += 1;
              hooks?.onReady?.();
              await new Promise<void>(() => undefined);
            },
          }) as unknown as MarmotAgentControlClient,
        statusSink: (patch) => {
          replacementHost.push(patch);
        },
      },
    );
    await waitFor(() => replacementHost.some((patch) => patch.connected === true));
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
    });

    rejectOld(new Error("secret stale account lookup"));
    await Promise.resolve();
    await Promise.resolve();

    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
      lastError: null,
    });
    expect(replacementHost.at(-1)).toMatchObject({
      running: true,
      connected: true,
    });
    expect(JSON.stringify({ hostPatches, replacementHost })).not.toContain("secret stale");

    let extraSubscribes = 0;
    const extraStop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
            async accountList() {
              return {
                type: "account_list",
                accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
              };
            },
            async *subscribeInbound() {
              extraSubscribes += 1;
            },
          }) as unknown as MarmotAgentControlClient,
      },
    );
    await Promise.resolve();
    expect(replacementSubscribes).toBe(1);
    expect(extraSubscribes).toBe(0);
    extraStop();
    replacementStop();
  });

  it("ignores a late accountList success after a replacement is acknowledged", async () => {
    let resolveOld!: () => void;
    const oldAccountList = new Promise<{
      type: "account_list";
      accounts: Array<{ account_id_hex: string; label: string; local_signing: boolean }>;
    }>((resolve) => {
      resolveOld = () =>
        resolve({
          type: "account_list",
          accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
        });
    });
    let oldSubscribes = 0;
    const oldStop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
            async accountList() {
              return oldAccountList;
            },
            async *subscribeInbound() {
              oldSubscribes += 1;
            },
          }) as unknown as MarmotAgentControlClient,
      },
    );
    oldStop();

    let replacementSubscribes = 0;
    const replacementStop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      () => undefined,
      {
        channelAccountId: "work",
        clientFactory: () =>
          ({
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
            ) {
              replacementSubscribes += 1;
              hooks?.onReady?.();
              await new Promise<void>(() => undefined);
            },
          }) as unknown as MarmotAgentControlClient,
      },
    );
    await waitFor(() => marmotInboundRuntimeSnapshot("work").connected === true);
    resolveOld();
    await Promise.resolve();
    await Promise.resolve();
    expect(oldSubscribes).toBe(0);
    expect(replacementSubscribes).toBe(1);
    expect(marmotInboundRuntimeSnapshot("work")).toMatchObject({
      running: true,
      connected: true,
    });
    replacementStop();
  });

  it("disposes failed attempts so a shared abort signal stays bounded", async () => {
    const signal = new AbortController();
    const abortCount = (): number => getEventListeners(signal.signal, "abort").length;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };

    for (let index = 0; index < 12; index += 1) {
      startMarmotInbound(api, () => undefined, {
        signal: signal.signal,
        clientFactory: () => {
          throw new Error("secret socket detail");
        },
      });
      expect(abortCount()).toBeLessThanOrEqual(1);
    }

    let pendingReject!: (error: Error) => void;
    startMarmotInbound(api, () => undefined, {
      signal: signal.signal,
      clientFactory: () =>
        ({
          async accountList() {
            return new Promise<never>((_resolve, reject) => {
              pendingReject = reject;
            });
          },
          async *subscribeInbound() {
            throw new Error("pending failure must not subscribe");
          },
        }) as unknown as MarmotAgentControlClient,
    });
    expect(abortCount()).toBe(1);
    pendingReject(new Error("secret account lookup"));
    await waitFor(() => abortCount() === 0);

    const readyPatches: Array<Record<string, unknown>> = [];
    const recovered = startMarmotInbound(api, () => undefined, {
      signal: signal.signal,
      statusSink: (patch) => {
        readyPatches.push(patch);
      },
      clientFactory: () => inboundStubClient([]),
    });
    await waitFor(() => readyPatches.some((patch) => patch.connected === true));
    expect(abortCount()).toBe(1);
    const patchesAfterReady = readyPatches.length;
    signal.abort();
    recovered();
    await Promise.resolve();
    expect(abortCount()).toBe(0);
    expect(readyPatches.length).toBe(patchesAfterReady + 1);
    expect(readyPatches.at(-1)).toMatchObject({ running: false, connected: false });
    expect(marmotInboundRuntimeSnapshot("default")).toMatchObject({
      running: false,
      connected: false,
    });
  });

  it("coalesces debounced bursts without dropping media, mentions, or reply context", async () => {
    const mediaA = mediaRef(HEX32("a1"), "a.png");
    const mediaB = mediaRef(HEX32("b2"), "b.png");
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
          channels: { marmot: { debounceMs: 25, profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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

  it("does not buffer an unlisted mutation actor as ambient context", async () => {
    const dispatched: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
            actor: { account_id_hex: HEX32("99"), display_name: null, is_self: false },
            replacement_text: "unauthorized",
            recorded_at: 122,
            target: {
              message_id_hex: HEX32("dd"),
              availability: "available",
              text_excerpt: "before",
              text_truncated: false,
              attachments_truncated: false,
            },
          },
          inboundEvent("cc", "ff"),
        ]),
    });

    await waitFor(() => dispatched.length > 0);
    stop();

    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]?.ambientContext ?? []).toEqual([]);
  });

  it("keeps ambient context when a non-triggering message is gated out", async () => {
    const attempted: MarmotInboundMessage[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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

  it("clears the group-info cache on subscription drop and re-establishment", async () => {
    vi.useFakeTimers();
    const cleared: string[] = [];
    let subscriptions = 0;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        ({
          async accountList() {
            return {
              type: "account_list",
              accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
            };
          },
          async *subscribeInbound(
            _filter?: unknown,
            signal?: AbortSignal,
            hooks?: { onReady?: () => void },
          ) {
            subscriptions += 1;
            hooks?.onReady?.();
            if (subscriptions === 1) {
              throw new Error("subscription dropped");
            }
            await new Promise<void>((resolve) => {
              if (signal?.aborted) {
                resolve();
              } else {
                signal?.addEventListener("abort", () => resolve(), { once: true });
              }
            });
          },
        }) as unknown as MarmotAgentControlClient,
      clearGroupActivationCache: () => {
        cleared.push(`clear-${subscriptions}`);
      },
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(cleared).toEqual(["clear-1"]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(cleared).toEqual(["clear-1", "clear-2"]);
    stop();
  });

  it("clears the group-info cache after a clean-EOF reconnect", async () => {
    vi.useFakeTimers();
    const cleared: string[] = [];
    let subscriptions = 0;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, () => {}, {
      clientFactory: () =>
        ({
          async accountList() {
            return {
              type: "account_list",
              accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
            };
          },
          async *subscribeInbound(
            _filter?: unknown,
            signal?: AbortSignal,
            hooks?: { onReady?: () => void },
          ) {
            subscriptions += 1;
            hooks?.onReady?.();
            if (subscriptions === 1) {
              return;
            }
            await new Promise<void>((resolve) => {
              if (signal?.aborted) {
                resolve();
              } else {
                signal?.addEventListener("abort", () => resolve(), { once: true });
              }
            });
          },
        }) as unknown as MarmotAgentControlClient,
      clearGroupActivationCache: () => {
        cleared.push(`clear-${subscriptions}`);
      },
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(cleared).toEqual([]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(cleared).toEqual(["clear-2"]);
    stop();
  });

  it("clears the whole group-activation cache on an inbound resync", async () => {
    let cleared = 0;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
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
      config: { channels: { marmot: { debounceMs: 10, profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb"), HEX32("bc")] } } } },
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
      channels: { marmot: { debounceMs: 25, profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } },
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
      channels: { marmot: { debounceMs: 25, profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } },
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

describe("startMarmotInbound with the real dispatcher cache", () => {
  function quietRuntime(): OpenClawChannelRuntime {
    return {
      routing: {
        resolveAgentRoute: () => ({
          agentId: "agent",
          accountId: "default",
          sessionKey: "agent:marmot:lifecycle",
        }),
      },
      session: {
        resolveStorePath: () => "/tmp/openclaw-marmot-lifecycle",
        recordInboundSession: vi.fn(),
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async () => undefined,
      },
    };
  }

  function countingGroupInfo(subject = "Project Marmot"): {
    client: MarmotDispatchClient;
    groupInfoCalls: () => number;
  } {
    let calls = 0;
    return {
      client: {
        async groupInfo(accountIdHex: string, groupIdHex: string) {
          calls += 1;
          return {
            type: "group_info",
            account_id_hex: accountIdHex,
            group_id_hex: groupIdHex,
            member_count: 5,
            is_direct: false,
            subject,
          };
        },
        async timelineList(accountIdHex: string, groupIdHex: string) {
          return {
            type: "timeline_page",
            account_id_hex: accountIdHex,
            group_id_hex: groupIdHex,
            messages: [],
            has_more_before: false,
            has_more_after: false,
          };
        },
      } as unknown as MarmotDispatchClient,
      groupInfoCalls: () => calls,
    };
  }

  it("invalidates on rename, clears on resync, and does not start a turn from the event", async () => {
    const { client, groupInfoCalls } = countingGroupInfo();
    const turns: string[] = [];
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: {
        ...quietRuntime(),
        reply: {
          dispatchReplyWithBufferedBlockDispatcher: async () => {
            turns.push("turn");
          },
        },
      },
      client,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
      authorizer: testAllowlistAuthorizer(),
    });
    const events: AgentControlEvent[] = [
      inboundEvent("cc", "d1"),
      {
        type: "group_state_changed",
        account_id_hex: HEX32("aa"),
        group_id_hex: HEX32("cc"),
        change: "group_renamed",
        detail: "Renamed",
      },
      inboundEvent("cc", "d2"),
      {
        type: "resync_required",
        account_id_hex: HEX32("aa"),
        group_id_hex: null,
        dropped_events: 2,
      },
      inboundEvent("cc", "d3"),
    ];
    let releaseNext!: () => void;
    let nextEvent = new Promise<void>((resolve) => {
      releaseNext = resolve;
    });
    const api: InboundPluginApi = {
      config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
      logger: noopLogger,
    };
    const stop = startMarmotInbound(api, dispatch, {
      clientFactory: () =>
        ({
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
          ) {
            hooks?.onReady?.();
            for (const event of events) {
              await nextEvent;
              nextEvent = new Promise<void>((resolve) => {
                releaseNext = resolve;
              });
              yield event;
            }
          },
        }) as unknown as MarmotAgentControlClient,
      invalidateGroupActivation: dispatch.invalidateGroupActivation,
      clearGroupActivationCache: dispatch.clearGroupActivationCache,
    });

    releaseNext();
    await waitFor(() => turns.length >= 1);
    expect(groupInfoCalls()).toBe(1);
    const afterFirst = turns.length;
    releaseNext();
    await waitFor(() => turns.length === afterFirst);
    expect(groupInfoCalls()).toBe(1);
    releaseNext();
    await waitFor(() => turns.length >= 2);
    expect(groupInfoCalls()).toBe(2);
    releaseNext();
    await new Promise((resolve) => setTimeout(resolve, 20));
    releaseNext();
    await waitFor(() => turns.length >= 3);
    stop();
    expect(turns).toHaveLength(3);
    expect(groupInfoCalls()).toBe(3);
  });

  it("refreshes group facts after a failed reconnect when wired to the real dispatcher", async () => {
    const { client, groupInfoCalls } = countingGroupInfo();
    const turns: string[] = [];
    const dispatch = createMarmotInboundDispatcher({
      cfg: {},
      runtimeChannel: {
        ...quietRuntime(),
        reply: {
          dispatchReplyWithBufferedBlockDispatcher: async () => {
            turns.push("turn");
          },
        },
      },
      client,
      channelAccountId: "default",
      groupActivation: "always",
      mentionPatterns: [],
      authorizer: testAllowlistAuthorizer(),
    });
    let subscriptions = 0;
    const stop = startMarmotInbound(
      {
        config: { channels: { marmot: { profileNameOnboarding: false,
                senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: noopLogger,
      },
      dispatch,
      {
        clientFactory: () =>
          ({
            async accountList() {
              return {
                type: "account_list",
                accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
              };
            },
            async *subscribeInbound(
              _filter?: unknown,
              signal?: AbortSignal,
              hooks?: { onReady?: () => void },
            ) {
              subscriptions += 1;
              hooks?.onReady?.();
              yield inboundEvent("cc", subscriptions === 1 ? "d1" : "d2");
              if (subscriptions === 1) {
                throw new Error("subscription dropped");
              }
              await new Promise<void>((resolve) => {
                if (signal?.aborted) {
                  resolve();
                } else {
                  signal?.addEventListener("abort", () => resolve(), { once: true });
                }
              });
            },
          }) as unknown as MarmotAgentControlClient,
        invalidateGroupActivation: dispatch.invalidateGroupActivation,
        clearGroupActivationCache: dispatch.clearGroupActivationCache,
      },
    );

    await waitFor(() => turns.length >= 1);
    expect(groupInfoCalls()).toBe(1);
    await waitFor(() => turns.length >= 2, 3_000);
    expect(groupInfoCalls()).toBe(2);
    stop();
  });
});

describe("syncMarmotAllowlist", () => {
  const SECRET_TOKEN = "secret-token-value";
  const SECRET_PATH = "/secret/token-file";
  const SECRET_ACCOUNT = HEX32("ee");
  const SECRET_ERROR = "secret socket detail";

  function allowlistStubClient(
    current: string[],
    options: {
      failAdds?: string[];
      failRemoves?: string[];
      failInitialList?: boolean;
      failReadBack?: boolean;
      mutateOnReadBack?: (effective: Set<string>) => void;
      onRemove?: (id: string) => void;
    } = {},
  ): {
    client: MarmotAgentControlClient;
    added: string[];
    removed: string[];
    effective: Set<string>;
  } {
    const added: string[] = [];
    const removed: string[] = [];
    const effective = new Set(current);
    const failAdds = new Set(options.failAdds ?? []);
    const failRemoves = new Set(options.failRemoves ?? []);
    let listCalls = 0;
    const client = {
      async accountList() {
        return {
          type: "account_list",
          accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
        };
      },
      async allowlistList() {
        listCalls += 1;
        if (listCalls === 1 && options.failInitialList) {
          throw new Error(SECRET_ERROR);
        }
        if (listCalls > 1) {
          if (options.failReadBack) {
            throw new Error(SECRET_ERROR);
          }
          options.mutateOnReadBack?.(effective);
        }
        return {
          type: "allowlist",
          account_id_hex: HEX32("aa"),
          welcomer_account_ids_hex: [...effective],
        };
      },
      async allowlistAdd(_account: string, id: string) {
        added.push(id);
        if (failAdds.has(id)) {
          throw new Error(SECRET_ERROR);
        }
        effective.add(id);
        return { type: "ack" };
      },
      async allowlistRemove(_account: string, id: string) {
        removed.push(id);
        if (failRemoves.has(id)) {
          throw new Error(SECRET_ERROR);
        }
        effective.delete(id);
        options.onRemove?.(id);
        return { type: "ack" };
      },
    } as unknown as MarmotAgentControlClient;
    return { client, added, removed, effective };
  }

  function expectNoSecrets(value: unknown): void {
    const serialized = JSON.stringify(value);
    expect(serialized).not.toContain(SECRET_TOKEN);
    expect(serialized).not.toContain(SECRET_PATH);
    expect(serialized).not.toContain(SECRET_ACCOUNT);
    expect(serialized).not.toContain(SECRET_ERROR);
  }

  it("mirrors configured dm.allowFrom into the wn-agent allowlist", async () => {
    const { client, added, effective } = allowlistStubClient([]);
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: noopLogger,
    };
    const result = await syncMarmotAllowlist(api, { clientFactory: () => client });
    expect(result).toEqual({ state: "reconciled" });
    expect(added).toEqual([HEX32("11")]);
    expect(effective.has(HEX32("11"))).toBe(true);
  });

  it("reports a superseded handover without warning when the signal aborts", async () => {
    const stale = HEX32("11");
    const { client, added, removed } = allowlistStubClient([stale]);
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("22")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };

    const result = await syncMarmotAllowlist(api, {
      clientFactory: () => client,
      signal: AbortSignal.abort(),
    });

    // A handover is not an operational failure, so it must not raise the
    // allowlist-failure warning operators are meant to act on.
    expect(result).toEqual({ state: "failed", reason: "superseded" });
    expect(warnings).toEqual([]);
    expect(added).toEqual([]);
    expect(removed).toEqual([]);
  });

  it("stops mutating partway through when the signal aborts mid-pass", async () => {
    const controller = new AbortController();
    const stale = [HEX32("11"), HEX32("22")];
    const { client, added, removed } = allowlistStubClient(stale, {
      onRemove: () => controller.abort(),
    });
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("33")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };

    const result = await syncMarmotAllowlist(api, {
      clientFactory: () => client,
      signal: controller.signal,
    });

    expect(result).toEqual({ state: "failed", reason: "superseded" });
    expect(removed).toHaveLength(1);
    expect(added).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it("is a no-op (no client used) when no allowFrom is configured", async () => {
    let used = false;
    const api: InboundPluginApi = { config: { channels: { marmot: {} } }, logger: noopLogger };
    const result = await syncMarmotAllowlist(api, {
      clientFactory: () => {
        used = true;
        return {} as unknown as MarmotAgentControlClient;
      },
    });
    expect(result).toEqual({ state: "unmanaged" });
    expect(used).toBe(false);
  });

  it("treats an explicit empty allowFrom as unmanaged even when a token file is missing", async () => {
    let used = false;
    const api: InboundPluginApi = {
      config: {
        channels: {
          marmot: { dm: { allowFrom: [] }, authTokenFile: SECRET_PATH },
        },
      },
      logger: noopLogger,
    };
    const result = await syncMarmotAllowlist(api, {
      clientFactory: () => {
        used = true;
        return {} as unknown as MarmotAgentControlClient;
      },
    });
    expect(result).toEqual({ state: "unmanaged" });
    expect(used).toBe(false);
  });

  it("returns config_resolution for an unknown multi-account id", async () => {
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { accounts: { default: {} } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };
    const result = await syncMarmotAllowlist(api, { channelAccountId: "missing" });
    expect(result).toEqual({ state: "failed", reason: "config_resolution" });
    expectNoSecrets(result);
    expectNoSecrets(warnings);
  });

  it("returns config_resolution when a managed policy cannot read its token file", async () => {
    const warnings: string[] = [];
    const previousToken = process.env.MARMOT_AGENT_AUTH_TOKEN;
    const previousTokenFile = process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
    delete process.env.MARMOT_AGENT_AUTH_TOKEN;
    delete process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
    try {
      const api: InboundPluginApi = {
        config: {
          channels: {
            marmot: { dm: { allowFrom: [HEX32("11")] }, authTokenFile: SECRET_PATH },
          },
        },
        logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
      };
      const result = await syncMarmotAllowlist(api);
      expect(result).toEqual({ state: "failed", reason: "config_resolution" });
      expectNoSecrets(result);
      expectNoSecrets(warnings);
    } finally {
      if (previousToken === undefined) {
        delete process.env.MARMOT_AGENT_AUTH_TOKEN;
      } else {
        process.env.MARMOT_AGENT_AUTH_TOKEN = previousToken;
      }
      if (previousTokenFile === undefined) {
        delete process.env.MARMOT_AGENT_AUTH_TOKEN_FILE;
      } else {
        process.env.MARMOT_AGENT_AUTH_TOKEN_FILE = previousTokenFile;
      }
    }
  });

  it("returns account_resolution when wn-agent has no local-signing account", async () => {
    const warnings: string[] = [];
    const client = {
      async accountList() {
        return { type: "account_list", accounts: [] };
      },
    } as unknown as MarmotAgentControlClient;
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };
    const result = await syncMarmotAllowlist(api, { clientFactory: () => client });
    expect(result).toEqual({ state: "failed", reason: "account_resolution" });
    expectNoSecrets(result);
    expectNoSecrets(warnings);
  });

  it("returns control when client construction or the initial list fails", async () => {
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };
    await expect(
      syncMarmotAllowlist(api, {
        clientFactory: () => {
          throw new Error(SECRET_ERROR);
        },
      }),
    ).resolves.toEqual({ state: "failed", reason: "control" });

    const { client } = allowlistStubClient([], { failInitialList: true });
    const listed = await syncMarmotAllowlist(api, { clientFactory: () => client });
    expect(listed).toEqual({ state: "failed", reason: "control" });
    expectNoSecrets(warnings);
  });

  it("returns unverified for partial mutation, readback failure, and concurrent divergence", async () => {
    const warnings: string[] = [];
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };

    const partialAdd = allowlistStubClient([], { failAdds: [HEX32("11")] });
    expect(
      await syncMarmotAllowlist(api, { clientFactory: () => partialAdd.client }),
    ).toEqual({ state: "failed", reason: "unverified" });

    const revoke = HEX32("99");
    const partialRemove = allowlistStubClient([revoke], { failRemoves: [revoke] });
    const removeApi: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };
    expect(
      await syncMarmotAllowlist(removeApi, { clientFactory: () => partialRemove.client }),
    ).toEqual({ state: "failed", reason: "unverified" });
    expect(warnings.some((message) => message.includes("revocation failed"))).toBe(true);
    expect(warnings.join(" ")).not.toContain(revoke);

    const readBack = allowlistStubClient([], { failReadBack: true });
    expect(
      await syncMarmotAllowlist(api, { clientFactory: () => readBack.client }),
    ).toEqual({ state: "failed", reason: "unverified" });

    const diverged = allowlistStubClient([], {
      mutateOnReadBack: (effective) => {
        effective.add(SECRET_ACCOUNT);
      },
    });
    expect(
      await syncMarmotAllowlist(api, { clientFactory: () => diverged.client }),
    ).toEqual({ state: "failed", reason: "unverified" });
    expectNoSecrets(warnings);
  });

  it("treats an ambiguous mutation as reconciled when the final readback matches", async () => {
    const { client, effective } = allowlistStubClient([], {
      failAdds: [HEX32("11")],
      mutateOnReadBack: (set) => {
        set.add(HEX32("11"));
      },
    });
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: noopLogger,
    };
    expect(await syncMarmotAllowlist(api, { clientFactory: () => client })).toEqual({
      state: "reconciled",
    });
    expect(effective.has(HEX32("11"))).toBe(true);
  });

  it("warns when a welcomer revocation cannot be applied", async () => {
    const stale = HEX32("99");
    const warnings: string[] = [];
    const { client } = allowlistStubClient([stale], { failRemoves: [stale] });
    const api: InboundPluginApi = {
      config: { channels: { marmot: { dm: { allowFrom: [HEX32("11")] } } } },
      logger: { info: () => {}, warn: (message: string) => warnings.push(message) },
    };

    const result = await syncMarmotAllowlist(api, { clientFactory: () => client });

    expect(result).toEqual({ state: "failed", reason: "unverified" });
    expect(warnings.some((message) => message.includes("revocation failed"))).toBe(true);
    expect(warnings.join(" ")).not.toContain(stale);
    expectNoSecrets(result);
  });
});
