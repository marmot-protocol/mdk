import { createServer, type Server, type Socket } from "node:net";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

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
});
