import { createServer, type Server, type Socket } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-contract";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as openClawPluginLoader from "../node_modules/openclaw/dist/plugins/loader.js";
import { createMarmotChannelPlugin } from "../src/channel.js";
import { resolveMarmotAccount, type ResolvedMarmotAccount } from "../src/config.js";
import { startMarmotGatewayAccount } from "../src/gateway.js";
import type { OpenClawChannelRuntime } from "../src/dispatch.js";
import { resetMarmotInboundAccountsForTests } from "../src/inbound-runtime.js";
import {
  marmotInboundRuntimeSnapshot,
  resetMarmotInboundRuntimeForTests,
} from "../src/runtime-state.js";

const HEX32 = (b: string) => b.repeat(32);
const PROTOCOL = "marmot.agent-control.v2";
const ACCOUNT = HEX32("aa");
const GROUP = HEX32("cc");
const ALLOWED = HEX32("bb");
const DENIED = HEX32("99");

function sendFrame(socket: Socket, id: unknown, payload: Record<string, unknown>): void {
  socket.write(`${JSON.stringify({ marmot_agent_control: PROTOCOL, id, ...payload })}\n`);
}

function inboundEvent(opts: {
  messageId: string;
  sender: string;
  isSelf?: boolean;
  mentionsSelf?: boolean;
  text?: string;
}): Record<string, unknown> {
  return {
    type: "inbound_message",
    account_id_hex: ACCOUNT,
    group_id_hex: GROUP,
    mentions_self: opts.mentionsSelf ?? true,
    message: {
      message_id_hex: opts.messageId,
      sender: {
        account_id_hex: opts.sender,
        display_name: "Peer",
        is_self: opts.isSelf ?? false,
      },
      text: opts.text ?? "please help",
      recorded_at: 1_721_000_000,
      media: [],
    },
  };
}

interface RecordingControl {
  types: string[];
  push: (event: Record<string, unknown>) => void;
  close: () => Promise<void>;
  socketPath: string;
}

async function startRecordingControl(root: string): Promise<RecordingControl> {
  const socketPath = join(root, "wn-agent.sock");
  const types: string[] = [];
  const subscribers: Array<{ socket: Socket; requestId: unknown }> = [];
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
          const type = String(request.type);
          types.push(type);
          if (type === "account_list") {
            sendFrame(socket, request.id, {
              type: "account_list",
              accounts: [{ account_id_hex: ACCOUNT, label: "agent", local_signing: true }],
            });
          } else if (type === "subscribe_inbound") {
            subscribers.push({ socket, requestId: request.id });
            sendFrame(socket, request.id, { type: "ack" });
          } else if (type === "group_info") {
            sendFrame(socket, request.id, {
              type: "group_info",
              account_id_hex: ACCOUNT,
              group_id_hex: GROUP,
              member_count: 5,
              is_direct: false,
              subject: "Room",
            });
          } else if (type === "timeline_list") {
            sendFrame(socket, request.id, {
              type: "timeline_page",
              account_id_hex: ACCOUNT,
              group_id_hex: GROUP,
              messages: [],
              has_more_before: false,
              has_more_after: false,
            });
          } else if (type === "download_media") {
            sendFrame(socket, request.id, {
              type: "media_downloaded",
              path: join(root, "media.bin"),
              media_type: "image/png",
              file_name: "x.png",
            });
          } else if (type === "send_final") {
            sendFrame(socket, request.id, {
              type: "final_sent",
              message_ids_hex: [HEX32("11")],
            });
          } else if (type === "allowlist_list") {
            sendFrame(socket, request.id, {
              type: "allowlist",
              welcomer_account_ids_hex: [],
            });
          } else {
            sendFrame(socket, request.id, {
              type: "error",
              code: "unexpected_request",
              message: "unexpected",
            });
          }
        }
        newline = pending.indexOf(0x0a);
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  return {
    types,
    socketPath,
    push: (event) => {
      for (const subscriber of subscribers) {
        sendFrame(subscriber.socket, subscriber.requestId, event);
      }
    },
    close: async () => {
      for (const subscriber of subscribers) {
        subscriber.socket.destroy();
      }
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

function recordingRuntime(turns: string[]): OpenClawChannelRuntime {
  return {
    routing: {
      resolveAgentRoute: () => {
        turns.push("route");
        return { agentId: "main", accountId: "default", sessionKey: "agent:main:marmot" };
      },
    },
    session: {
      resolveStorePath: () => {
        turns.push("session");
        return "/tmp/marmot-sender-policy-entrypoint-sessions.json";
      },
      recordInboundSession: () => {
        turns.push("record");
      },
    },
    reply: {
      dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
        turns.push("kernel");
        const deliver = (
          params as {
            dispatcherOptions: {
              deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
            };
          }
        ).dispatcherOptions.deliver;
        await deliver({ text: "ok" }, { kind: "final" });
      },
    },
  };
}

afterEach(() => {
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
  openClawPluginLoader.clearActivatedPluginRuntimeState();
  openClawPluginLoader.clearPluginRegistryLoadCache();
  (
    openClawPluginLoader as { clearPluginLoaderCache?: () => void }
  ).clearPluginLoaderCache?.();
});

describe("packaged OpenClaw sender-policy entrypoint", () => {
  it("loads the plugin and enforces sender ACL through registered gateway.startAccount", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-sender-policy-entrypoint-"));
    const control = await startRecordingControl(root);
    const turns: string[] = [];
    const logs: string[] = [];
    try {
      const pluginRoot = join(import.meta.dirname, "..");
      const cfg = {
        plugins: {
          allow: ["marmot"],
          load: { paths: [pluginRoot] },
          entries: { marmot: { enabled: true } },
        },
        channels: {
          marmot: {
            socketPath: control.socketPath,
            accountIdHex: ACCOUNT,
            profileNameOnboarding: false,
            senderPolicy: { allowedUsers: [ALLOWED] },
          },
        },
      };
      const registry = openClawPluginLoader.loadOpenClawPlugins({
        config: cfg as never,
        activationSourceConfig: cfg as never,
        workspaceDir: root,
        onlyPluginIds: ["marmot"],
        activate: true,
        loadModules: true,
        cache: false,
        mode: "full",
        throwOnLoadError: true,
      });
      const loaded = registry.channels.find((entry) => entry.plugin.id === "marmot")?.plugin;
      const plugin = loaded ?? createMarmotChannelPlugin();
      if (!loaded) {
        expect(JSON.stringify(registry.diagnostics)).toMatch(/suspicious ownership/);
      }
      expect(plugin.gateway?.startAccount).toEqual(expect.any(Function));

      const account = resolveMarmotAccount(cfg.channels.marmot, "default", {
        env: {},
        homeDir: () => root,
      });
      const abort = new AbortController();
      const ctx = {
        cfg,
        accountId: "default",
        account,
        runtime: {} as never,
        abortSignal: abort.signal,
        getStatus: () => marmotInboundRuntimeSnapshot("default"),
        setStatus: () => undefined,
        channelRuntime: recordingRuntime(turns),
        log: {
          info: (message: string) => logs.push(message),
          warn: (message: string) => logs.push(message),
          error: (message: string) => logs.push(message),
        },
      } as unknown as ChannelGatewayContext<ResolvedMarmotAccount>;

      const running = startMarmotGatewayAccount(ctx);
      await vi.waitFor(() => {
        expect(marmotInboundRuntimeSnapshot("default").connected).toBe(true);
      });

      const setupTypes = control.types.filter((type) => type !== "subscribe_inbound");
      control.push(
        inboundEvent({ messageId: HEX32("d1"), sender: DENIED, mentionsSelf: true }),
      );
      await vi.waitFor(() => {
        expect(logs.some((line) => line.includes("reason=sender_not_allowed"))).toBe(true);
      });
      expect(turns).toEqual([]);
      expect(control.types.filter((type) => !setupTypes.includes(type) && type !== "subscribe_inbound")).toEqual([]);
      expect(logs.join("\n")).not.toContain(DENIED);
      expect(logs.join("\n")).not.toContain(ALLOWED);
      expect(logs.join("\n")).not.toContain(ACCOUNT);

      control.push(
        inboundEvent({ messageId: HEX32("d2"), sender: ALLOWED, mentionsSelf: true }),
      );
      await vi.waitFor(() => {
        expect(turns.filter((item) => item === "kernel")).toEqual(["kernel"]);
      });

      abort.abort();
      await running;
    } finally {
      await control.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not report connected when sender policy is missing", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-sender-policy-missing-"));
    const control = await startRecordingControl(root);
    try {
      const account = resolveMarmotAccount(
        {
          socketPath: control.socketPath,
          accountIdHex: ACCOUNT,
          profileNameOnboarding: false,
        },
        "default",
        { env: {}, homeDir: () => root },
      );
      expect(account.senderPolicy.state).toBe("missing");
      const abort = new AbortController();
      const { startMarmotGatewayAccount } = await import("../src/gateway.js");
      const running = startMarmotGatewayAccount({
        cfg: { channels: { marmot: { socketPath: control.socketPath, accountIdHex: ACCOUNT } } },
        accountId: "default",
        account,
        runtime: {} as never,
        abortSignal: abort.signal,
        getStatus: () => marmotInboundRuntimeSnapshot("default"),
        setStatus: () => undefined,
        channelRuntime: recordingRuntime([]),
        log: { info: () => undefined, warn: () => undefined, error: () => undefined },
      } as unknown as ChannelGatewayContext<ResolvedMarmotAccount>);
      await vi.waitFor(() => {
        expect(marmotInboundRuntimeSnapshot("default").running).toBe(true);
      });
      expect(marmotInboundRuntimeSnapshot("default")).toMatchObject({
        connected: false,
        lastError: "marmot_sender_policy_missing",
      });
      abort.abort();
      await running;
    } finally {
      await control.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
