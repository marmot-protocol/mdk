import { createServer, type Server, type Socket } from "node:net";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { buildChannelInboundEventContext } from "openclaw/plugin-sdk/channel-inbound";
import { recordInboundSession } from "openclaw/plugin-sdk/conversation-runtime";
import {
  clearSessionStoreCacheForTest,
  getSessionEntry,
  resolveStorePath as resolveHostStorePath,
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
import { materializeOwnedPluginRoot } from "./isolated-plugin-root.js";
import { testAllowlistAuthorizer, testInboundActor } from "./sender-policy-fixtures.js";

const HEX32 = (byte: string): string => byte.repeat(32);
const PROTOCOL = "marmot.agent-control.v2";

function isUnsafeSqliteRuntime(error: unknown): boolean {
  return error instanceof Error && /SQLite support is unavailable or unsafe/.test(error.message);
}

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
    const pluginRoot = await materializeOwnedPluginRoot(root);
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
    const loadedIds = registry.channels.map((entry) => entry.plugin.id);
    if (!loadedIds.includes("marmot")) {
      throw new Error(
        `Marmot plugin registration required; diagnostics=${JSON.stringify(registry.diagnostics)}`,
      );
    }
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
    try {
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
    } catch (error) {
      // Beta send_final stages through the host SQLite delivery queue. Node
      // runtimes whose embedded SQLite is outside OpenClaw's WAL-safe range
      // cannot exercise that queue; the adapter mapping remains covered on
      // stable and on WAL-safe Node.
      if (!isUnsafeSqliteRuntime(error)) {
        throw error;
      }
    }
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
      authorizer: testAllowlistAuthorizer(),
      deliverInboundReply: deliverInboundReply as never,
    });

    await expect(
      dispatch({
        accountIdHex: HEX32("aa"),
        groupIdHex: HEX32("cc"),
        messageIdHex: HEX32("dd"),
        senderAccountIdHex: HEX32("bb"),
        sender: testInboundActor(),
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
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false, senderPolicy: { allowedUsers: [HEX32("bb"), HEX32("bc")] } } },
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
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false, senderPolicy: { allowedUsers: [HEX32("bb")] } } },
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
          channels: { marmot: { debounceMs: 1, profileNameOnboarding: false, senderPolicy: { allowedUsers: [HEX32("bb")] } } },
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
  const NATIVE_SESSION_AGENT_ID = "agent";

  type NativeSessionRecord = {
    groupId?: string;
    subject?: string;
    channel?: string;
    origin?: { label?: string };
    delivery?: {
      channel?: string;
      context?: { channel?: string };
      origin?: { label?: string; provider?: string };
    };
  };

  type NativeSessionRead =
    | { status: "ok"; session?: NativeSessionRecord }
    | { status: "unavailable" };

  let sessionStoreUnavailable = false;

  afterEach(() => {
    sessionStoreUnavailable = false;
    clearSessionStoreCacheSafe();
  });

  function clearSessionStoreCacheSafe(): void {
    try {
      clearSessionStoreCacheForTest();
    } catch (error) {
      if (!isUnsafeSqliteRuntime(error)) {
        throw error;
      }
    }
  }

  function resolveNativeStorePath(storePath: string): string {
    return resolveHostStorePath(storePath, { agentId: NATIVE_SESSION_AGENT_ID });
  }

  function sessionOriginLabel(session: NativeSessionRecord): string | undefined {
    return session.origin?.label ?? session.delivery?.origin?.label;
  }

  function sessionChannel(session: NativeSessionRecord): string | undefined {
    return (
      session.channel ??
      session.delivery?.channel ??
      session.delivery?.context?.channel ??
      session.delivery?.origin?.provider
    );
  }

  function markSessionStoreUnavailable(error: unknown): boolean {
    if (!isUnsafeSqliteRuntime(error)) {
      return false;
    }
    sessionStoreUnavailable = true;
    return true;
  }

  function readNativeSession(storePath: string, sessionKey: string): NativeSessionRead {
    if (sessionStoreUnavailable) {
      return { status: "unavailable" };
    }
    try {
      // storePath is already agent-resolved. Passing agentId again makes the
      // beta host prefer the default isolated home store and return ok/undefined
      // for the file the turn just wrote.
      return {
        status: "ok",
        session: getSessionEntry({
          storePath,
          sessionKey,
        }) as NativeSessionRecord | undefined,
      };
    } catch (error) {
      if (markSessionStoreUnavailable(error)) {
        return { status: "unavailable" };
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
  }): Promise<NativeSessionRead> {
    const storePath = resolveNativeStorePath(params.storePath);
    let meta: Promise<unknown> | undefined;
    try {
      await recordInboundSession({
        storePath,
        sessionKey: params.sessionKey,
        ctx: params.ctx as never,
        groupResolution: params.groupResolution,
        createIfMissing: true,
        onRecordError: (error) => {
          if (!markSessionStoreUnavailable(error)) {
            throw error;
          }
        },
        trackSessionMetaTask: (task) => {
          meta = task;
        },
      });
      await meta;
      return readNativeSession(storePath, params.sessionKey);
    } catch (error) {
      if (markSessionStoreUnavailable(error)) {
        return { status: "unavailable" };
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

  function createNativeDispatchHarness(opts: {
    storePath: string;
    groupIdHex: string;
    sessionKey?: string;
    client: MarmotDispatchClient;
    groupActivation?: "always" | "mention";
    mentionPatterns?: string[];
    accountIdHex?: string;
    senderAccountIdHex?: string;
  }): {
    dispatch: ReturnType<typeof createMarmotInboundDispatcher>;
    captured: Array<{ ctx: Record<string, unknown> }>;
  } {
    const captured: Array<{ ctx: Record<string, unknown> }> = [];
    const groupIdHex = opts.groupIdHex;
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
        resolveStorePath: (store, options) =>
          resolveHostStorePath(String(store ?? opts.storePath), {
            agentId:
              (options as { agentId?: string } | undefined)?.agentId ?? NATIVE_SESSION_AGENT_ID,
          }),
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
              onRecordError: (error) => {
                if (!markSessionStoreUnavailable(error)) {
                  throw error;
                }
              },
              trackSessionMetaTask: (task) => {
                meta = task;
                input.trackSessionMetaTask?.(task);
              },
            });
            await meta;
          } catch (error) {
            if (!markSessionStoreUnavailable(error)) {
              throw error;
            }
          }
        },
      },
      reply: {
        dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
          captured.push({ ctx: (params as { ctx: Record<string, unknown> }).ctx });
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
      client: opts.client,
      channelAccountId: "default",
      groupActivation: opts.groupActivation ?? "always",
      mentionPatterns: opts.mentionPatterns ?? [],
      authorizer: testAllowlistAuthorizer(opts.accountIdHex ?? HEX32("aa"), [
        opts.senderAccountIdHex ?? HEX32("bb"),
      ]),
      deliverInboundReply: deliverInboundReply as never,
    });
    return { dispatch, captured };
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
  }): Promise<{
    ctx: Record<string, unknown>;
    session: NativeSessionRecord | undefined;
    sessionRead: NativeSessionRead;
  }> {
    const accountIdHex = opts.accountIdHex ?? HEX32("aa");
    const groupIdHex = opts.groupIdHex;
    const senderAccountIdHex = opts.senderAccountIdHex ?? HEX32("bb");
    const sessionKey = opts.sessionKey ?? `agent:marmot:${groupIdHex}`;
    const { dispatch, captured } = createNativeDispatchHarness({
      storePath: opts.storePath,
      groupIdHex,
      sessionKey: opts.sessionKey,
      client: opts.client ?? groupInfoClient({ subject: opts.subject, isDirect: opts.isDirect }),
      groupActivation: opts.groupActivation,
      mentionPatterns: opts.mentionPatterns,
      accountIdHex,
      senderAccountIdHex,
    });
    await dispatch({
      accountIdHex,
      groupIdHex,
      messageIdHex: HEX32("dd"),
      senderAccountIdHex,
      sender: testInboundActor(senderAccountIdHex),
      text: opts.text ?? "hello",
      mentionsSelf: opts.mentionsSelf,
    });
    const capturedCtx = captured[0]?.ctx;
    if (!capturedCtx) {
      throw new Error("turn did not build a native context");
    }
    const sessionRead = readNativeSession(resolveNativeStorePath(opts.storePath), sessionKey);
    return {
      ctx: capturedCtx,
      session: sessionRead.status === "ok" ? sessionRead.session : undefined,
      sessionRead,
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
        const { ctx, session, sessionRead } = await dispatchNamedTurn({
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
          expect(sessionOriginLabel(session)).toBe("Project Marmot");
          expect(session.groupId).toBe(groupIdHex);
          expect(sessionChannel(session)).toBe("marmot");
        } else {
          expect(sessionRead.status).toBe("unavailable");
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
        clearSessionStoreCacheSafe();
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
      if (first.session && second.session && third.session) {
        expect(first.session.groupId).toBe(groupA);
        expect(second.session.groupId).toBe(groupB);
        expect(third.session.groupId).toBe(group16);
        expect(first.session.subject).toBe("Shared");
        expect(second.session.subject).toBe("Shared");
      } else {
        expect(first.sessionRead.status).toBe("unavailable");
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
        expect(first.sessionRead.status).toBe("unavailable");
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

  it("refreshes one live dispatcher native session after rename, resync, and reconnect", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-native-live-lifecycle-"));
    const storePath = join(root, "sessions.json");
    const groupIdHex = HEX32("cc");
    const accountIdHex = HEX32("aa");
    const sender = HEX32("bb");
    const sessionKey = `agent:marmot:${groupIdHex}`;
    let subject: unknown = "Name A";
    let groupInfoCalls = 0;
    const client = {
      async groupInfo(requestAccountIdHex: string, requestGroupIdHex: string) {
        groupInfoCalls += 1;
        return {
          type: "group_info",
          account_id_hex: requestAccountIdHex,
          group_id_hex: requestGroupIdHex,
          member_count: 5,
          is_direct: false,
          subject,
        };
      },
      async timelineList(requestAccountIdHex: string, requestGroupIdHex: string) {
        return {
          type: "timeline_page" as const,
          account_id_hex: requestAccountIdHex,
          group_id_hex: requestGroupIdHex,
          messages: [],
          has_more_before: false,
          has_more_after: false,
        };
      },
    } as unknown as MarmotDispatchClient;
    const { dispatch, captured } = createNativeDispatchHarness({
      storePath,
      groupIdHex,
      sessionKey,
      client,
    });

    type Queued = AgentControlEvent | "fail" | "eof";
    const queued: Queued[] = [];
    const waiters: Array<() => void> = [];
    const push = (item: Queued): void => {
      queued.push(item);
      waiters.shift()?.();
    };
    const take = async (signal?: AbortSignal): Promise<Queued | undefined> => {
      if (queued.length > 0) {
        return queued.shift();
      }
      await new Promise<void>((resolve) => {
        const finish = (): void => {
          const index = waiters.indexOf(finish);
          if (index >= 0) {
            waiters.splice(index, 1);
          }
          resolve();
        };
        waiters.push(finish);
        signal?.addEventListener("abort", finish, { once: true });
      });
      return queued.shift();
    };

    const inbound = (idByte: string): AgentControlEvent => ({
      type: "inbound_message",
      account_id_hex: accountIdHex,
      group_id_hex: groupIdHex,
      message: {
        message_id_hex: HEX32(idByte),
        sender: { account_id_hex: sender, display_name: null, is_self: false },
        text: "hello",
        recorded_at: 123,
        media: [],
      },
    });
    const renamed = (): AgentControlEvent => ({
      type: "group_state_changed",
      account_id_hex: accountIdHex,
      group_id_hex: groupIdHex,
      change: "group_renamed",
      detail: "ignored",
    });
    const resync = (): AgentControlEvent => ({
      type: "resync_required",
      account_id_hex: accountIdHex,
      group_id_hex: null,
      dropped_events: 1,
    });

    let subscriptions = 0;
    const stop = startMarmotInbound(
      {
        config: { channels: { marmot: { debounceMs: 0, profileNameOnboarding: false, senderPolicy: { allowedUsers: [HEX32("bb")] } } } },
        logger: { info: () => undefined, warn: () => undefined },
      },
      dispatch,
      {
        clientFactory: () =>
          ({
            async accountList() {
              return {
                type: "account_list",
                accounts: [{ account_id_hex: accountIdHex, label: "agent", local_signing: true }],
              };
            },
            async *subscribeInbound(
              _filter?: unknown,
              signal?: AbortSignal,
              hooks?: { onReady?: () => void },
            ) {
              subscriptions += 1;
              hooks?.onReady?.();
              while (!signal?.aborted) {
                const item = await take(signal);
                if (item === undefined || signal?.aborted) {
                  return;
                }
                if (item === "fail") {
                  throw new Error("subscription dropped");
                }
                if (item === "eof") {
                  return;
                }
                yield item;
              }
            },
          }) as unknown as MarmotAgentControlClient,
        invalidateGroupActivation: dispatch.invalidateGroupActivation,
        clearGroupActivationCache: dispatch.clearGroupActivationCache,
        reconnectDelayMs: 1,
        maxReconnectDelayMs: 1,
      },
    );

    const readSession = (): NativeSessionRead =>
      readNativeSession(resolveNativeStorePath(storePath), sessionKey);
    const expectPersisted = async (expectedSubject: string): Promise<void> => {
      // WAL-unsafe Node cannot persist. On a supported runtime the planned
      // native-session regression must observe the recorded subject/group id.
      // Poll: the host may finish session meta after the turn is captured.
      await vi.waitFor(() => {
        const sessionRead = readSession();
        if (sessionStoreUnavailable) {
          return;
        }
        expect(sessionRead.status).toBe("ok");
        if (sessionRead.status !== "ok") {
          return;
        }
        expect(sessionRead.session).toBeDefined();
        expect(sessionRead.session?.groupId).toBe(groupIdHex);
        expect(
          sessionRead.session?.subject ?? sessionOriginLabel(sessionRead.session ?? {}),
        ).toBe(expectedSubject);
      }, { timeout: 10_000 });
    };
    const expectIdentity = (ctx: Record<string, unknown>): void => {
      expect(ctx.ChatId).toBe(groupIdHex);
      expect(ctx.To).toBe(groupIdHex);
      expect(ctx.OriginatingTo ?? ctx.To).toBe(groupIdHex);
      expect(ctx.SessionKey).toBe(sessionKey);
      expect(ctx.From).toBe(sender);
    };
    const waitForTurns = async (count: number): Promise<void> => {
      await vi.waitFor(() => expect(captured.length).toBe(count), { timeout: 10_000 });
    };
    const expectNoExtraTurn = async (count: number): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(captured.length).toBe(count);
    };

    try {
      await vi.waitFor(() => expect(subscriptions).toBe(1), { timeout: 10_000 });
      push(inbound("01"));
      await waitForTurns(1);
      expect(captured[0]?.ctx.ConversationLabel).toBe("Name A");
      expect(captured[0]?.ctx.GroupSubject).toBe("Name A");
      expectIdentity(captured[0]!.ctx);
      expect(groupInfoCalls).toBe(1);
      await expectPersisted("Name A");

      push(inbound("02"));
      await waitForTurns(2);
      expect(captured[1]?.ctx.ConversationLabel).toBe("Name A");
      expectIdentity(captured[1]!.ctx);
      expect(groupInfoCalls).toBe(1);

      const beforeRename = readSession();
      subject = "Name B";
      push(renamed());
      await expectNoExtraTurn(2);
      expect(groupInfoCalls).toBe(1);
      const afterRenameEvent = readSession();
      if (beforeRename.status === "ok" && afterRenameEvent.status === "ok") {
        expect(afterRenameEvent.session?.subject).toBe(beforeRename.session?.subject);
        expect(afterRenameEvent.session?.groupId).toBe(groupIdHex);
      }

      push(inbound("03"));
      await waitForTurns(3);
      expect(captured[2]?.ctx.ConversationLabel).toBe("Name B");
      expect(captured[2]?.ctx.GroupSubject).toBe("Name B");
      expectIdentity(captured[2]!.ctx);
      expect(groupInfoCalls).toBe(2);
      await expectPersisted("Name B");

      push(inbound("04"));
      await waitForTurns(4);
      expect(captured[3]?.ctx.ConversationLabel).toBe("Name B");
      expect(groupInfoCalls).toBe(2);

      const beforeBlank = readSession();
      subject = "";
      push(renamed());
      await expectNoExtraTurn(4);
      expect(groupInfoCalls).toBe(2);
      const afterBlankEvent = readSession();
      if (beforeBlank.status === "ok" && afterBlankEvent.status === "ok") {
        expect(afterBlankEvent.session?.subject).toBe(beforeBlank.session?.subject);
      }

      push(inbound("05"));
      await waitForTurns(5);
      expect(captured[4]?.ctx.GroupSubject).toBeUndefined();
      expectIdentity(captured[4]!.ctx);
      expect(groupInfoCalls).toBe(3);
      await expectPersisted("Name B");

      push(resync());
      await expectNoExtraTurn(5);
      expect(groupInfoCalls).toBe(3);
      push(inbound("06"));
      await waitForTurns(6);
      expect(captured[5]?.ctx.GroupSubject).toBeUndefined();
      expectIdentity(captured[5]!.ctx);
      expect(groupInfoCalls).toBe(4);
      await expectPersisted("Name B");

      push("fail");
      await vi.waitFor(() => expect(subscriptions).toBe(2), { timeout: 10_000 });
      push(inbound("07"));
      await waitForTurns(7);
      expectIdentity(captured[6]!.ctx);
      expect(groupInfoCalls).toBe(5);
      await expectPersisted("Name B");

      push("eof");
      await vi.waitFor(() => expect(subscriptions).toBe(3), { timeout: 10_000 });
      push(inbound("08"));
      await waitForTurns(8);
      expectIdentity(captured[7]!.ctx);
      expect(captured[7]?.ctx.ChatId).toBe(groupIdHex);
      expect(groupInfoCalls).toBe(6);
      await expectPersisted("Name B");
    } finally {
      stop();
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  }, 30_000);

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
      if (recorded.status === "ok") {
        expect(recorded.session?.groupId).toBe(groupIdHex);
        expect(recorded.session?.groupId).not.toBe(sender);
      } else {
        expect(recorded.status).toBe("unavailable");
      }

      clearSessionStoreCacheSafe();
      const defaultStore = join(root, "default-sessions.json");
      const withoutResolution = await recordSessionAndWait({
        storePath: defaultStore,
        sessionKey: `agent:marmot:${groupIdHex}`,
        ctx,
      });
      if (withoutResolution.status === "ok" && withoutResolution.session) {
        expect(withoutResolution.session.groupId).not.toBe(groupIdHex);
      }
    } finally {
      clearSessionStoreCacheSafe();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    }
  });
});
