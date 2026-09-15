import { createServer, type Server, type Socket } from "node:net";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";
import { recordInboundSession } from "openclaw/plugin-sdk/conversation-runtime";
import {
  clearSessionStoreCacheForTest,
  loadSessionStore,
} from "openclaw/plugin-sdk/session-store-runtime";
import { afterEach, describe, expect, it, vi } from "vitest";

// Deliberate test-only internal import: OpenClaw exposes neither its plugin
// loader nor generic message-action runner through a supported SDK subpath.
// Re-verify this stable loader entry whenever the pinned SDK is bumped.
import * as openClawPluginLoader from "../node_modules/openclaw/dist/plugins/loader.js";

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
const PROTOCOL = "marmot.agent-control.v2";

interface RecordedControlSend {
  request: Record<string, unknown>;
  stagedPath?: string;
  stagedBytes?: Buffer;
}

type RunMessageAction = (input: {
  cfg: unknown;
  action: "send";
  params: Record<string, unknown>;
  agentId: string;
  senderIsOwner: boolean;
}) => Promise<unknown>;

/** Load the installed host's private action runner without pinning its hashed chunk name. */
async function loadInstalledRunMessageAction(): Promise<RunMessageAction> {
  const distDir = join(import.meta.dirname, "..", "node_modules", "openclaw", "dist");
  const runnerFile = (await readdir(distDir)).find(
    (entry) => entry.startsWith("message-action-runner-") && entry.endsWith(".js"),
  );
  if (!runnerFile) {
    throw new Error("installed OpenClaw has no message-action runner chunk");
  }
  const module = (await import(pathToFileURL(join(distDir, runnerFile)).href)) as Record<
    string,
    unknown
  >;
  const runner = Object.values(module).find(
    (value) => typeof value === "function" && value.name === "runMessageAction",
  );
  if (!runner) {
    throw new Error("installed OpenClaw message-action runner export was not found");
  }
  return runner as RunMessageAction;
}

function sendControlResponse(
  socket: Socket,
  id: unknown,
  payload: Record<string, unknown>,
): void {
  socket.write(`${JSON.stringify({ marmot_agent_control: PROTOCOL, id, ...payload })}\n`);
}

/** Minimal wn-agent socket that records durable text or staged media sends. */
function startControlServer(
  socketPath: string,
  recorded: RecordedControlSend[],
): Promise<Server> {
  const server = createServer((socket) => {
    let pending = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      let newline = pending.indexOf(0x0a);
      while (newline !== -1) {
        const line = pending.subarray(0, newline);
        pending = pending.subarray(newline + 1);
        if (line.length > 0) {
          const request = JSON.parse(line.toString("utf8")) as Record<string, unknown>;
          void (async () => {
            if (request.type === "send_final") {
              recorded.push({ request });
              sendControlResponse(socket, request.id, {
                type: "final_sent",
                message_ids_hex: [HEX32("11")],
              });
              return;
            }
            if (request.type !== "send_media") {
              sendControlResponse(socket, request.id, {
                type: "error",
                code: "unexpected_request",
                message: `unexpected request: ${String(request.type)}`,
              });
              return;
            }
            const attachment = (request.attachments as Array<Record<string, unknown>>)[0]!;
            const stagedPath = String(attachment.path);
            recorded.push({
              request,
              stagedPath,
              stagedBytes: await readFile(stagedPath),
            });
            sendControlResponse(socket, request.id, {
              type: "final_sent",
              message_ids_hex: [HEX32("11")],
            });
          })().catch((error: unknown) => socket.destroy(error as Error));
        }
        newline = pending.indexOf(0x0a);
      }
    });
    socket.on("error", () => undefined);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve(server));
  });
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

/** Run the installed generic message action through the loaded Marmot plugin. */
async function runPublicSend(
  buildParams: (workspaceDir: string) => Promise<Record<string, unknown>>,
): Promise<RecordedControlSend> {
  const root = await mkdtemp(join(tmpdir(), "marmot-host-media-contract-"));
  const workspaceDir = join(root, "workspace");
  const outboundMediaDir = join(root, "outbound-media");
  const socketPath = join(root, "wn-agent.sock");
  const recorded: RecordedControlSend[] = [];
  const previousOutboundMediaDir = process.env.MARMOT_OUTBOUND_MEDIA_DIR;
  let server: Server | undefined;
  try {
    await mkdir(workspaceDir, { recursive: true, mode: 0o700 });
    process.env.MARMOT_OUTBOUND_MEDIA_DIR = outboundMediaDir;
    server = await startControlServer(socketPath, recorded);
    const pluginRoot = join(import.meta.dirname, "..");
    const cfg = {
      plugins: {
        allow: ["marmot"],
        load: { paths: [pluginRoot] },
        entries: { marmot: { enabled: true } },
      },
      agents: { list: [{ id: "main", workspace: workspaceDir }] },
      tools: { fs: { workspaceOnly: false } },
      channels: {
        marmot: {
          socketPath,
          accountIdHex: HEX32("aa"),
        },
      },
    };
    // Import the runner before activation: older hosts initialize additional
    // runtime projections while evaluating this private chunk.
    const runMessageAction = await loadInstalledRunMessageAction();
    const registry = openClawPluginLoader.loadOpenClawPlugins({
      config: cfg as never,
      activationSourceConfig: cfg as never,
      workspaceDir,
      onlyPluginIds: ["marmot"],
      activate: true,
      loadModules: true,
      cache: false,
      mode: "full",
      throwOnLoadError: true,
    });
    expect(
      registry.channels.map((entry) => entry.plugin.id),
      JSON.stringify(registry.diagnostics),
    ).toContain("marmot");
    await runMessageAction({
      cfg,
      action: "send",
      params: await buildParams(workspaceDir),
      agentId: "main",
      senderIsOwner: true,
    });
    expect(recorded).toHaveLength(1);
    const sent = recorded[0]!;
    if (sent.stagedPath) {
      await expect(access(sent.stagedPath)).rejects.toThrow();
    }
    return sent;
  } finally {
    if (server) {
      await closeServer(server);
    }
    if (previousOutboundMediaDir === undefined) {
      delete process.env.MARMOT_OUTBOUND_MEDIA_DIR;
    } else {
      process.env.MARMOT_OUTBOUND_MEDIA_DIR = previousOutboundMediaDir;
    }
    await rm(root, { recursive: true, force: true });
  }
}

afterEach(() => {
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
  openClawPluginLoader.clearActivatedPluginRuntimeState();
  openClawPluginLoader.clearPluginRegistryLoadCache();
  const clearPluginLoaderCache = (
    openClawPluginLoader as typeof openClawPluginLoader & {
      clearPluginLoaderCache?: () => void;
    }
  ).clearPluginLoaderCache;
  clearPluginLoaderCache?.();
});

/**
 * Exercise Marmot's production adapters against the installed OpenClaw host.
 * This file is also run by openclaw-host-compat.sh against the supported beta.
 */
describe("installed OpenClaw inbound host contract", () => {
  it("sends an authorized workspace image through the public message action", async () => {
    const imageBytes = Buffer.from("workspace-image-bytes");
    const sent = await runPublicSend(async (workspaceDir) => {
      const imagePath = join(workspaceDir, "generated.png");
      await writeFile(imagePath, imageBytes);
      return {
        channel: "marmot",
        target: HEX32("cc"),
        message: "workspace image",
        media: imagePath,
      };
    });

    expect(sent.stagedBytes).toEqual(imageBytes);
    expect(sent.request).toMatchObject({
      type: "send_media",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      caption: "workspace image",
      attachments: [{ media_type: "image/png", file_name: "generated.png" }],
    });
  });

  it("sends a buffer and filename through the public message action", async () => {
    const imageBytes = Buffer.from("buffer-image-bytes");
    const sent = await runPublicSend(async () => ({
      channel: "marmot",
      target: HEX32("cc"),
      message: "buffer image",
      buffer: imageBytes.toString("base64"),
      filename: "from-buffer.png",
      contentType: "image/png",
    }));

    expect(sent.stagedBytes).toEqual(imageBytes);
    expect(sent.request).toMatchObject({
      type: "send_media",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      caption: "buffer image",
      attachments: [{ media_type: "image/png", file_name: "from-buffer.png" }],
    });
  });

  it("passes the host durable queue identity into send_final", async () => {
    const sent = await runPublicSend(async () => ({
      channel: "marmot",
      target: HEX32("cc"),
      message: "durable text",
      bestEffort: false,
    }));

    expect(sent.request).toMatchObject({
      type: "send_final",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      text: "durable text",
      idempotency_key: expect.stringMatching(/^marmot-final-v1:[0-9a-f]{64}$/),
    });
  });

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

  it("releases the stable debounce lane when the group queue adopts a batch", async () => {
    vi.useFakeTimers();
    const groupIdHex = HEX32("cc");
    const senderA = HEX32("bb");
    const senderB = HEX32("bc");
    const messageIdA1 = HEX32("d1");
    const messageIdA2 = HEX32("d2");
    const messageIdB1 = HEX32("d3");
    const inbound = (messageIdHex: string, senderAccountIdHex: string): AgentControlEvent => ({
      type: "inbound_message",
      account_id_hex: HEX32("aa"),
      group_id_hex: groupIdHex,
      message: {
        message_id_hex: messageIdHex,
        sender: { account_id_hex: senderAccountIdHex, display_name: null, is_self: false },
        text: messageIdHex,
        recorded_at: 123,
        media: [],
      },
    });
    let emitA2!: () => void;
    let emitB1!: () => void;
    const waitForA2 = new Promise<void>((resolve) => {
      emitA2 = resolve;
    });
    const waitForB1 = new Promise<void>((resolve) => {
      emitB1 = resolve;
    });
    const client = {
      accountList: async () => ({
        type: "account_list" as const,
        accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
      }),
      async *subscribeInbound(
        _filter?: unknown,
        signal?: AbortSignal,
        hooks?: { onReady?: () => void },
      ): AsyncGenerator<AgentControlEvent> {
        hooks?.onReady?.();
        yield inbound(messageIdA1, senderA);
        await waitForA2;
        yield inbound(messageIdA2, senderA);
        await waitForB1;
        yield inbound(messageIdB1, senderB);
        await new Promise<void>((resolve) => {
          if (signal?.aborted) {
            resolve();
          } else {
            signal?.addEventListener("abort", () => resolve(), { once: true });
          }
        });
      },
    } as unknown as MarmotAgentControlClient;
    const started: string[] = [];
    const completions = new Map<string, () => void>();
    const stop = startMarmotInbound(
      {
        config: {
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false } },
        },
        logger: { info: () => undefined, warn: () => undefined },
      },
      async (message) => {
        started.push(message.messageIdHex);
        await new Promise<void>((resolve) => completions.set(message.messageIdHex, resolve));
      },
      { clientFactory: () => client },
    );

    try {
      await vi.advanceTimersByTimeAsync(1);
      expect(started).toEqual([messageIdA1]);

      emitA2();
      await vi.advanceTimersByTimeAsync(1);
      emitB1();
      await vi.advanceTimersByTimeAsync(1);
      expect(started).toEqual([messageIdA1]);

      completions.get(messageIdA1)?.();
      await vi.advanceTimersByTimeAsync(0);
      expect(started).toEqual([messageIdA1, messageIdA2]);

      completions.get(messageIdA2)?.();
      await vi.advanceTimersByTimeAsync(0);
      expect(started).toEqual([messageIdA1, messageIdA2, messageIdB1]);
      completions.get(messageIdB1)?.();
    } finally {
      emitA2();
      emitB1();
      for (const resolve of completions.values()) {
        resolve();
      }
      stop();
      vi.useRealTimers();
    }
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

  betaContract("releases a debounce key when the group queue adopts the batch", async () => {
    const events: AgentControlEvent[] = Array.from({ length: 33 }, (_, index) => ({
      type: "inbound_message",
      account_id_hex: HEX32("aa"),
      group_id_hex: HEX32("cc"),
      message: {
        message_id_hex: (index + 1).toString(16).padStart(64, "0"),
        sender: { account_id_hex: HEX32("bb"), display_name: null, is_self: false },
        text: `message-${index}`,
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
        for (const event of events) {
          yield event;
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        await new Promise<void>((resolve) => {
          if (_signal?.aborted) {
            resolve();
          } else {
            _signal?.addEventListener("abort", () => resolve(), { once: true });
          }
        });
      },
    } as unknown as MarmotAgentControlClient;
    let releaseFirst!: () => void;
    const firstCompletion = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const dispatched = vi.fn(async (_message: MarmotInboundMessage) => {
      if (dispatched.mock.calls.length === 1) {
        await firstCompletion;
      }
    });
    const warnings: string[] = [];
    const stop = startMarmotInbound(
      {
        config: {
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false } },
        },
        logger: { info: () => undefined, warn: (message) => warnings.push(message) },
      },
      dispatched,
      { clientFactory: () => client },
    );

    try {
      await vi.waitFor(() =>
        expect(warnings).toContain(
          "marmot: inbound queue overloaded (reason=per_group_depth, active_groups=1, max_depth_per_group=32, max_tracked_groups=256)",
        ),
      );
      expect(warnings.join(" ")).not.toContain("inbound debounce overloaded");
    } finally {
      releaseFirst();
      stop();
    }
  });
});

describe("OpenClaw native group subject and session metadata", () => {
  const HEX16 = (byte: string): string => byte.repeat(16);

  afterEach(() => {
    clearSessionStoreCacheSafe();
  });

  function isUnsafeSqliteRuntime(error: unknown): boolean {
    return error instanceof Error && /SQLite support is unavailable or unsafe/.test(error.message);
  }

  function clearSessionStoreCacheSafe(): void {
    try {
      clearSessionStoreCacheForTest();
    } catch (error) {
      if (!isUnsafeSqliteRuntime(error)) {
        throw error;
      }
    }
  }

  function loadSessionStoreIfSafe(
    storePath: string,
  ): Record<string, { groupId?: string; subject?: string; channel?: string; origin?: { label?: string } }> | undefined {
    try {
      return loadSessionStore(storePath) as Record<
        string,
        { groupId?: string; subject?: string; channel?: string; origin?: { label?: string } }
      >;
    } catch (error) {
      if (isUnsafeSqliteRuntime(error)) {
        return undefined;
      }
      throw error;
    }
  }

  async function recordSessionAndWait(params: {
    storePath: string;
    sessionKey: string;
    ctx: unknown;
    groupResolution?: {
      key: string;
      channel: string;
      id: string;
      chatType: "group";
    };
  }): Promise<boolean> {
    let meta: Promise<unknown> | undefined;
    try {
      await recordInboundSession({
        storePath: params.storePath,
        sessionKey: params.sessionKey,
        ctx: params.ctx as never,
        groupResolution: params.groupResolution,
        createIfMissing: true,
        onRecordError: () => undefined,
        trackSessionMetaTask: (task) => {
          meta = task;
        },
      });
      await meta;
      return true;
    } catch (error) {
      if (isUnsafeSqliteRuntime(error)) {
        return false;
      }
      throw error;
    }
  }

  function groupInfoClient(opts: {
    subject?: unknown;
    isDirect?: boolean;
    byGroup?: Record<string, { subject?: unknown; isDirect?: boolean }>;
  } = {}): MarmotDispatchClient {
    return {
      async groupInfo(accountIdHex: string, groupIdHex: string) {
        const override = opts.byGroup?.[groupIdHex];
        const isDirect = override?.isDirect ?? opts.isDirect ?? false;
        return {
          type: "group_info",
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          member_count: isDirect ? 2 : 5,
          is_direct: isDirect,
          subject: override?.subject ?? opts.subject ?? null,
        };
      },
      async timelineList(accountIdHex: string, groupIdHex: string) {
        return {
          type: "timeline_page" as const,
          account_id_hex: accountIdHex,
          group_id_hex: groupIdHex,
          messages: [],
          has_more_before: false,
          has_more_after: false,
        };
      },
    } as unknown as MarmotDispatchClient;
  }

  async function dispatchNamedTurn(opts: {
    storePath: string;
    groupIdHex: string;
    accountIdHex?: string;
    senderAccountIdHex?: string;
    sessionKey?: string;
    groupActivation?: "always" | "mention";
    mentionPatterns?: string[];
    mentionsSelf?: boolean;
    text?: string;
    isDirect?: boolean;
    subject?: unknown;
    client?: MarmotDispatchClient;
  }): Promise<{ ctx: Record<string, unknown>; session: Record<string, unknown> | undefined }> {
    let capturedCtx: Record<string, unknown> | undefined;
    const accountIdHex = opts.accountIdHex ?? HEX32("aa");
    const groupIdHex = opts.groupIdHex;
    const senderAccountIdHex = opts.senderAccountIdHex ?? HEX32("bb");
    const sessionKey = opts.sessionKey ?? `agent:marmot:${groupIdHex}`;
    const deliverInboundReply = vi.fn(async () => ({
      status: "handled_visible" as const,
      delivery: {},
    }));
    const runtimeChannel: OpenClawChannelRuntime = {
      routing: {
        resolveAgentRoute: (input) => {
          const peer = (input as { peer?: { id?: string } }).peer;
          return {
            agentId: "agent",
            accountId: "default",
            sessionKey: opts.sessionKey ?? `agent:marmot:${peer?.id ?? groupIdHex}`,
          };
        },
      },
      session: {
        resolveStorePath: (store) => String(store ?? opts.storePath),
        recordInboundSession: async (params: unknown) => {
          const input = params as {
            storePath: string;
            sessionKey: string;
            ctx: unknown;
            groupResolution?: {
              key: string;
              channel: string;
              id: string;
              chatType: "group";
            };
            createIfMissing?: boolean;
            trackSessionMetaTask?: (task: Promise<unknown>) => void;
            onRecordError?: (err: unknown) => void;
          };
          let meta: Promise<unknown> | undefined;
          try {
            await recordInboundSession({
              ...input,
              ctx: input.ctx as never,
              onRecordError: input.onRecordError ?? (() => undefined),
              trackSessionMetaTask: (task) => {
                meta = task;
                input.trackSessionMetaTask?.(task);
              },
            });
            await meta;
          } catch (error) {
            if (!isUnsafeSqliteRuntime(error)) {
              throw error;
            }
          }
        },
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          capturedCtx = (params as { ctx: Record<string, unknown> }).ctx;
          const deliver = (params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }).dispatcherOptions.deliver;
          await deliver({ text: "native-subject-reply" }, { kind: "final" });
          return { counts: {} };
        },
      },
    };
    const dispatch = createMarmotInboundDispatcher({
      cfg: { session: { store: opts.storePath } },
      runtimeChannel,
      client: opts.client ?? groupInfoClient({ subject: opts.subject, isDirect: opts.isDirect }),
      channelAccountId: "default",
      groupActivation: opts.groupActivation ?? "always",
      mentionPatterns: opts.mentionPatterns ?? [],
      deliverInboundReply: deliverInboundReply as never,
    });
    await dispatch({
      accountIdHex,
      groupIdHex,
      messageIdHex: HEX32("dd"),
      senderAccountIdHex,
      text: opts.text ?? "hello",
      mentionsSelf: opts.mentionsSelf,
    });
    if (!capturedCtx) {
      throw new Error("turn did not build a native context");
    }
    const store = loadSessionStoreIfSafe(opts.storePath);
    return {
      ctx: capturedCtx,
      session: store?.[sessionKey],
    };
  }

  it("maps a named group onto native ConversationLabel/GroupSubject and session metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-subject-"));
    const storePath = join(root, "sessions.json");
    const groupIdHex = HEX32("cc");
    const sender = HEX32("bb");
    try {
      const unlabeledControl = await buildChannelInboundEventContext({
        channel: "marmot",
        accountId: "default",
        messageId: HEX32("dd"),
        timestamp: 1_721_000_000_000,
        from: sender,
        sender: { id: sender },
        conversation: { kind: "group", id: groupIdHex },
        route: {
          agentId: "agent",
          accountId: "default",
          routeSessionKey: `agent:marmot:${groupIdHex}`,
        },
        reply: { to: groupIdHex },
        message: { rawBody: "hello", bodyForAgent: "hello" },
      });
      const cases: Array<{
        groupActivation: "always" | "mention";
        mentionsSelf?: boolean;
        mentionPatterns?: string[];
        text?: string;
        isDirect?: boolean;
      }> = [
        { groupActivation: "always" },
        { groupActivation: "mention", mentionsSelf: true },
        { groupActivation: "mention", mentionPatterns: ["marvin"], text: "hey Marvin" },
        { groupActivation: "mention", isDirect: true },
      ];
      for (const activation of cases) {
        clearSessionStoreCacheSafe();
        const { ctx, session } = await dispatchNamedTurn({
          storePath,
          groupIdHex,
          senderAccountIdHex: sender,
          subject: "Project Marmot",
          ...activation,
        });
        expect(ctx.ConversationLabel).toBe("Project Marmot");
        expect(ctx.GroupSubject).toBe("Project Marmot");
        expect(ctx.ChatId).toBe(groupIdHex);
        expect(ctx.To).toBe(groupIdHex);
        expect(ctx.OriginatingTo ?? ctx.To).toBe(groupIdHex);
        expect(ctx.SessionKey).toBe(`agent:marmot:${groupIdHex}`);
        expect(ctx.From).toBe(sender);
        if (session) {
          expect(session.subject).toBe("Project Marmot");
          expect((session.origin as { label?: string } | undefined)?.label).toBe("Project Marmot");
          expect(session.groupId).toBe(groupIdHex);
          expect(session.channel).toBe("marmot");
        } else {
          expect(loadSessionStoreIfSafe(storePath)).toBeUndefined();
        }
        expect(unlabeledControl.ConversationLabel).not.toBe("Project Marmot");
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it("matches the unlabeled SDK control case and does not coerce malformed subjects", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-unlabeled-"));
    const storePath = join(root, "sessions.json");
    const groupIdHex = HEX32("cc");
    const sender = HEX32("bb");
    try {
      const control = await buildChannelInboundEventContext({
        channel: "marmot",
        accountId: "default",
        messageId: HEX32("dd"),
        timestamp: 1_721_000_000_000,
        from: sender,
        sender: { id: sender },
        conversation: { kind: "group", id: groupIdHex },
        route: {
          agentId: "agent",
          accountId: "default",
          routeSessionKey: `agent:marmot:${groupIdHex}`,
        },
        reply: { to: groupIdHex },
        message: { rawBody: "hello", bodyForAgent: "hello" },
      });
      for (const subject of [null, "", "   ", 12, { name: "nope" }]) {
        clearSessionStoreCacheForTest();
        const { ctx } = await dispatchNamedTurn({
          storePath,
          groupIdHex,
          senderAccountIdHex: sender,
          subject,
        });
        expect(ctx.ConversationLabel).toBe(control.ConversationLabel);
        expect(ctx.GroupSubject).toBe(control.GroupSubject);
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it("keeps same-label groups and a 16-byte MLS id on distinct native sessions", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-isolation-"));
    const storePath = join(root, "sessions.json");
    const groupA = HEX32("c1");
    const groupB = HEX32("c2");
    const group16 = HEX16("ab");
    try {
      const first = await dispatchNamedTurn({ storePath, groupIdHex: groupA, subject: "Shared" });
      const second = await dispatchNamedTurn({ storePath, groupIdHex: groupB, subject: "Shared" });
      const third = await dispatchNamedTurn({ storePath, groupIdHex: group16, subject: "Shared" });
      expect(first.ctx.ChatId).toBe(groupA);
      expect(second.ctx.ChatId).toBe(groupB);
      expect(third.ctx.ChatId).toBe(group16);
      expect(first.ctx.SessionKey).toBe(`agent:marmot:${groupA}`);
      expect(second.ctx.SessionKey).toBe(`agent:marmot:${groupB}`);
      expect(third.ctx.SessionKey).toBe(`agent:marmot:${group16}`);
      const store = loadSessionStoreIfSafe(storePath);
      if (store) {
        expect(store[`agent:marmot:${groupA}`]?.groupId).toBe(groupA);
        expect(store[`agent:marmot:${groupB}`]?.groupId).toBe(groupB);
        expect(store[`agent:marmot:${group16}`]?.groupId).toBe(group16);
        expect(store[`agent:marmot:${groupA}`]?.subject).toBe("Shared");
        expect(store[`agent:marmot:${groupB}`]?.subject).toBe("Shared");
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it("updates the existing native session after rename and retains a host subject when later unlabeled", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-rename-"));
    const storePath = join(root, "sessions.json");
    const groupIdHex = HEX32("cc");
    let subject: unknown = "Name A";
    const client = groupInfoClient({
      get subject() {
        return subject;
      },
    });
    try {
      const first = await dispatchNamedTurn({
        storePath,
        groupIdHex,
        client,
        subject: "Name A",
      });
      if (first.session) {
        expect(first.session.subject).toBe("Name A");
      } else {
        expect(loadSessionStoreIfSafe(storePath)).toBeUndefined();
      }

      subject = "Name B";
      const renamed = await dispatchNamedTurn({
        storePath,
        groupIdHex,
        client,
        subject: "Name B",
      });
      expect(renamed.ctx.ConversationLabel).toBe("Name B");
      if (renamed.session) {
        expect(renamed.session.subject).toBe("Name B");
        expect(renamed.session.groupId).toBe(groupIdHex);
      }

      subject = "";
      const unlabeled = await dispatchNamedTurn({
        storePath,
        groupIdHex,
        client,
        subject: "",
      });
      expect(unlabeled.ctx.GroupSubject).toBeUndefined();
      if (unlabeled.session) {
        expect(unlabeled.session.groupId).toBe(groupIdHex);
        expect(unlabeled.session.subject).toBe("Name B");
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it("binds session group metadata to the full group id rather than the sender", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-resolution-"));
    const storePath = join(root, "sessions.json");
    const groupIdHex = HEX32("cc");
    const sender = HEX32("bb");
    try {
      const ctx = await buildChannelInboundEventContext({
        channel: "marmot",
        accountId: "default",
        messageId: HEX32("dd"),
        timestamp: 1_721_000_000_000,
        from: sender,
        sender: { id: sender },
        conversation: { kind: "group", id: groupIdHex, label: "Project Marmot" },
        route: {
          agentId: "agent",
          accountId: "default",
          routeSessionKey: `agent:marmot:${groupIdHex}`,
        },
        reply: { to: groupIdHex },
        message: { rawBody: "hello", bodyForAgent: "hello" },
      });
      const recorded = await recordSessionAndWait({
        storePath,
        sessionKey: `agent:marmot:${groupIdHex}`,
        ctx,
        groupResolution: {
          key: `marmot:group:${groupIdHex}`,
          channel: "marmot",
          id: groupIdHex,
          chatType: "group",
        },
      });
      const withResolution = loadSessionStoreIfSafe(storePath)?.[`agent:marmot:${groupIdHex}`];
      if (recorded && withResolution) {
        expect(withResolution.groupId).toBe(groupIdHex);
        expect(withResolution.groupId).not.toBe(sender);
      } else {
        expect(withResolution).toBeUndefined();
      }

      clearSessionStoreCacheSafe();
      const defaultStore = join(root, "default-sessions.json");
      await recordSessionAndWait({
        storePath: defaultStore,
        sessionKey: `agent:marmot:${groupIdHex}`,
        ctx,
      });
      const withoutResolution = loadSessionStoreIfSafe(defaultStore)?.[`agent:marmot:${groupIdHex}`];
      if (withoutResolution) {
        expect(withoutResolution.groupId).not.toBe(groupIdHex);
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });
});
