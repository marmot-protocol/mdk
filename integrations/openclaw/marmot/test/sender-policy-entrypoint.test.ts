import { createServer, type Server, type Socket } from "node:net";
import { access, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChannelGatewayContext } from "openclaw/plugin-sdk/channel-contract";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as openClawPluginLoader from "../node_modules/openclaw/dist/plugins/loader.js";
import { resolveMarmotAccount, type ResolvedMarmotAccount } from "../src/config.js";
import type { OpenClawChannelRuntime } from "../src/dispatch.js";
import { resetMarmotInboundAccountsForTests } from "../src/inbound-runtime.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";
import { materializeOwnedPluginRoot } from "./isolated-plugin-root.js";

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

interface RegisteredTextSend {
  (
    ctx: {
      cfg: unknown;
      accountId?: string;
      to: string;
      text: string;
      replyToId?: string;
      deliveryQueueId: string;
    },
  ): Promise<unknown>;
}

function inboundReplyTarget(ctx: Record<string, unknown>): { to: string; replyToId?: string } {
  const reply = ctx.reply as { to?: string; replyToId?: string } | undefined;
  const to =
    (typeof reply?.to === "string" && reply.to) ||
    (typeof ctx.OriginatingTo === "string" && ctx.OriginatingTo) ||
    (typeof ctx.To === "string" && ctx.To) ||
    "";
  if (!to) {
    throw new Error("registered Marmot send is missing a destination");
  }
  const replyToId =
    (typeof reply?.replyToId === "string" && reply.replyToId) ||
    (typeof ctx.MessageSid === "string" && ctx.MessageSid) ||
    undefined;
  return { to, ...(replyToId ? { replyToId } : {}) };
}

function recordingRuntime(
  turns: string[],
  sessionStorePath: string,
  sendText?: RegisteredTextSend,
): OpenClawChannelRuntime {
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
        return sessionStorePath;
      },
      recordInboundSession: () => {
        turns.push("record");
      },
    },
    reply: {
      dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
        turns.push("kernel");
        const typed = params as {
          ctx: Record<string, unknown>;
          cfg?: unknown;
          dispatcherOptions: {
            deliver: (payload: { text: string }, info: { kind: "final" }) => Promise<void>;
          };
        };
        if (sendText) {
          const target = inboundReplyTarget(typed.ctx ?? {});
          await sendText({
            cfg: typed.cfg,
            accountId: "default",
            to: target.to,
            text: "ok",
            replyToId: target.replyToId,
            deliveryQueueId: "entrypoint-authorized-turn:0",
          });
          turns.push("durable_final");
          return;
        }
        await typed.dispatcherOptions.deliver({ text: "ok" }, { kind: "final" });
        turns.push("durable_final");
      },
    },
  };
}

function isolateOpenClawState(root: string): { restore: () => void } {
  const previousHome = process.env.OPENCLAW_HOME;
  const previousState = process.env.OPENCLAW_STATE_DIR;
  process.env.OPENCLAW_HOME = join(root, "openclaw-home");
  process.env.OPENCLAW_STATE_DIR = join(root, "openclaw-state");
  return {
    restore() {
      if (previousHome === undefined) {
        delete process.env.OPENCLAW_HOME;
      } else {
        process.env.OPENCLAW_HOME = previousHome;
      }
      if (previousState === undefined) {
        delete process.env.OPENCLAW_STATE_DIR;
      } else {
        process.env.OPENCLAW_STATE_DIR = previousState;
      }
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

function loadRegisteredMarmotPlugin(cfg: Record<string, unknown>, workspaceDir: string) {
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
  const plugin = registry.channels.find((entry) => entry.plugin.id === "marmot")?.plugin;
  if (!plugin) {
    throw new Error(
      `Marmot plugin registration required; diagnostics=${JSON.stringify(registry.diagnostics)}`,
    );
  }
  if (typeof plugin.gateway?.startAccount !== "function") {
    throw new Error("registered Marmot plugin is missing gateway.startAccount");
  }
  return plugin;
}

function registeredTextSend(plugin: {
  message?: { send?: { text?: (ctx: never) => Promise<unknown> } };
}): RegisteredTextSend {
  const send = plugin.message?.send?.text;
  if (typeof send !== "function") {
    throw new Error("registered Marmot plugin is missing message.send.text");
  }
  return (ctx) => send(ctx as never);
}

function eventEffects(types: string[], setupTypes: string[]): string[] {
  return types.filter((type) => !setupTypes.includes(type) && type !== "subscribe_inbound");
}

function hostStatusContext(
  cfg: Record<string, unknown>,
  account: ResolvedMarmotAccount,
  options: {
    abort: AbortController;
    turns: string[];
    logs: string[];
    sessionStorePath: string;
    sendText?: RegisteredTextSend;
    accountId?: string;
  },
): {
  ctx: ChannelGatewayContext<ResolvedMarmotAccount>;
  snapshots: Array<Record<string, unknown>>;
} {
  const snapshots: Array<Record<string, unknown>> = [];
  const accountId = options.accountId ?? "default";
  const ctx = {
    cfg,
    accountId,
    account,
    runtime: {} as never,
    abortSignal: options.abort.signal,
    getStatus: () =>
      snapshots.at(-1) ?? { accountId, running: false, connected: false, lastError: null },
    setStatus: (next: Record<string, unknown>) => {
      snapshots.push(next);
    },
    channelRuntime: recordingRuntime(options.turns, options.sessionStorePath, options.sendText),
    log: {
      info: (message: string) => options.logs.push(message),
      warn: (message: string) => options.logs.push(message),
      error: (message: string) => options.logs.push(message),
    },
  } as unknown as ChannelGatewayContext<ResolvedMarmotAccount>;
  return { ctx, snapshots };
}

async function preparePackagedHost(root: string): Promise<{
  pluginRoot: string;
  sessionStorePath: string;
  restoreState: () => void;
}> {
  const pluginRoot = await materializeOwnedPluginRoot(root);
  const workspace = join(root, "workspace");
  const sessionStorePath = join(root, "sessions.json");
  await mkdir(join(root, "openclaw-home"), { recursive: true, mode: 0o700 });
  await mkdir(join(root, "openclaw-state"), { recursive: true, mode: 0o700 });
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  return {
    pluginRoot,
    sessionStorePath,
    restoreState: isolateOpenClawState(root).restore,
  };
}

function packagedConfig(
  pluginRoot: string,
  workspace: string,
  channel: Record<string, unknown>,
): Record<string, unknown> {
  return {
    plugins: {
      allow: ["marmot"],
      load: { paths: [pluginRoot] },
      entries: { marmot: { enabled: true } },
    },
    agents: { list: [{ id: "main", workspace }] },
    channels: { marmot: channel },
  };
}

describe("packaged OpenClaw sender-policy entrypoint", () => {
  it("does not treat a delivery-queue identity failure as a durable final", async () => {
    const turns: string[] = [];
    const runtime = recordingRuntime(turns, "/tmp/marmot-sender-policy-entrypoint-sessions.json");
    await expect(
      runtime.reply.dispatchReplyWithBufferedBlockDispatcher({
        dispatcherOptions: {
          deliver: async () => {
            throw new Error("marmot: durable text send requires OpenClaw delivery queue identity");
          },
        },
      }),
    ).rejects.toThrow(/delivery queue identity/);
    expect(turns).toEqual(["kernel"]);
    expect(turns.includes("durable_final")).toBe(false);
  });

  it("loads the plugin and enforces sender ACL through registered gateway.startAccount", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-sender-policy-entrypoint-"));
    const control = await startRecordingControl(root);
    const turns: string[] = [];
    const logs: string[] = [];
    const host = await preparePackagedHost(root);
    try {
      const channel = {
        socketPath: control.socketPath,
        accountIdHex: ACCOUNT,
        profileNameOnboarding: false,
        debounceMs: 40,
        senderPolicy: { allowedUsers: [ALLOWED] },
      };
      const cfg = packagedConfig(host.pluginRoot, join(root, "workspace"), channel);
      const plugin = loadRegisteredMarmotPlugin(cfg, root);
      const account = resolveMarmotAccount(channel, "default", {
        env: {},
        homeDir: () => root,
      });
      const abort = new AbortController();
      const { ctx, snapshots } = hostStatusContext(cfg, account, {
        abort,
        turns,
        logs,
        sessionStorePath: host.sessionStorePath,
        sendText: registeredTextSend(plugin),
      });
      const running = plugin.gateway!.startAccount!(ctx);
      try {
        await vi.waitFor(() => {
          expect(snapshots.at(-1)).toMatchObject({ running: true, connected: true });
        });

        const setupTypes = control.types.filter((type) => type !== "subscribe_inbound");
        const deniedCases = [
          inboundEvent({ messageId: HEX32("d1"), sender: DENIED, mentionsSelf: true }),
          inboundEvent({ messageId: HEX32("d3"), sender: ALLOWED, isSelf: true }),
          inboundEvent({
            messageId: HEX32("d4"),
            sender: "not-a-valid-account-id",
            mentionsSelf: true,
          }),
        ];
        for (const event of deniedCases) {
          const before = logs.length;
          control.push(event);
          await vi.waitFor(() => {
            expect(logs.length).toBeGreaterThan(before);
          });
        }
        expect(turns).toEqual([]);
        expect(eventEffects(control.types, setupTypes)).toEqual([]);
        expect(logs.some((line) => line.includes("reason=sender_not_allowed"))).toBe(true);
        expect(logs.some((line) => line.includes("reason=self_sender"))).toBe(true);
        expect(logs.some((line) => line.includes("reason=malformed_sender"))).toBe(true);
        expect(logs.join("\n")).not.toContain(DENIED);
        expect(logs.join("\n")).not.toContain(ALLOWED);
        expect(logs.join("\n")).not.toContain(ACCOUNT);

        control.push(inboundEvent({ messageId: HEX32("d2"), sender: ALLOWED, mentionsSelf: true }));
        control.push(inboundEvent({ messageId: HEX32("d5"), sender: ALLOWED, mentionsSelf: true }));
        await vi.waitFor(() => {
          expect(turns.filter((item) => item === "kernel")).toEqual(["kernel"]);
          expect(turns.filter((item) => item === "durable_final")).toEqual(["durable_final"]);
          expect(control.types.filter((type) => type === "send_final")).toEqual(["send_final"]);
        });
      } finally {
        abort.abort();
        await running.catch(() => undefined);
      }
    } finally {
      host.restoreState();
      await control.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("denies unauthorized senders before profile onboarding side effects", async () => {
    const root = await mkdtemp(join(tmpdir(), "marmot-sender-policy-onboarding-"));
    const control = await startRecordingControl(root);
    const turns: string[] = [];
    const logs: string[] = [];
    const onboardingPath = join(root, "profile-onboarding.json");
    const host = await preparePackagedHost(root);
    try {
      const channel = {
        socketPath: control.socketPath,
        accountIdHex: ACCOUNT,
        profileNameOnboarding: true,
        debounceMs: 40,
        senderPolicy: { allowedUsers: [ALLOWED] },
      };
      const cfg = packagedConfig(host.pluginRoot, join(root, "workspace"), channel);
      const plugin = loadRegisteredMarmotPlugin(cfg, root);
      const account = resolveMarmotAccount(channel, "default", {
        env: { MARMOT_PROFILE_ONBOARDING_STATE: onboardingPath },
        homeDir: () => root,
      });
      expect(account.profileNameOnboarding).toBe(true);
      expect(account.profileOnboardingStatePath).toBe(onboardingPath);
      const abort = new AbortController();
      const { ctx, snapshots } = hostStatusContext(cfg, account, {
        abort,
        turns,
        logs,
        sessionStorePath: host.sessionStorePath,
      });
      const running = plugin.gateway!.startAccount!(ctx);
      try {
        await vi.waitFor(() => {
          expect(snapshots.at(-1)).toMatchObject({ running: true, connected: true });
        });
        const setupTypes = control.types.filter((type) => type !== "subscribe_inbound");
        control.push(inboundEvent({ messageId: HEX32("d7"), sender: DENIED, mentionsSelf: true }));
        await vi.waitFor(() => {
          expect(logs.some((line) => line.includes("reason=sender_not_allowed"))).toBe(true);
        });
        expect(turns).toEqual([]);
        expect(eventEffects(control.types, setupTypes)).toEqual([]);
        expect(control.types.includes("send_final")).toBe(false);
        expect(control.types.includes("account_publish_profile")).toBe(false);
        expect(control.types.includes("account_profile_lookup")).toBe(false);
        await expect(access(onboardingPath)).rejects.toThrow();
        expect(logs.join("\n")).not.toContain(DENIED);
        expect(logs.join("\n")).not.toContain(ALLOWED);
        expect(logs.join("\n")).not.toContain(ACCOUNT);
      } finally {
        abort.abort();
        await running.catch(() => undefined);
      }
    } finally {
      host.restoreState();
      await control.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("does not report connected when sender policy is missing or invalid", async () => {
    for (const senderPolicy of [undefined, { allowedUsers: ["nope"] }]) {
      const root = await mkdtemp(join(tmpdir(), "marmot-sender-policy-unready-"));
      const control = await startRecordingControl(root);
      const turns: string[] = [];
      const logs: string[] = [];
      const host = await preparePackagedHost(root);
      try {
        const channel = {
          socketPath: control.socketPath,
          accountIdHex: ACCOUNT,
          profileNameOnboarding: false,
          ...(senderPolicy ? { senderPolicy } : {}),
        };
        const cfg = packagedConfig(host.pluginRoot, join(root, "workspace"), channel);
        const plugin = loadRegisteredMarmotPlugin(cfg, root);
        const account = resolveMarmotAccount(channel, "default", {
          env: {},
          homeDir: () => root,
        });
        expect(account.senderPolicy.state).toBe(senderPolicy ? "invalid" : "missing");
        const abort = new AbortController();
        const { ctx, snapshots } = hostStatusContext(cfg, account, {
          abort,
          turns,
          logs,
          sessionStorePath: host.sessionStorePath,
        });
        const running = plugin.gateway!.startAccount!(ctx);
        try {
          await vi.waitFor(() => {
            expect(snapshots.at(-1)).toMatchObject({ running: true });
          });
          expect(snapshots.at(-1)).toMatchObject({
            connected: false,
            lastError: senderPolicy ? "marmot_sender_policy_invalid" : "marmot_sender_policy_missing",
          });
          await vi.waitFor(() => {
            expect(control.types.includes("subscribe_inbound")).toBe(true);
          });
          const setupTypes = control.types.filter((type) => type !== "subscribe_inbound");
          control.push(inboundEvent({ messageId: HEX32("d6"), sender: ALLOWED, mentionsSelf: true }));
          await vi.waitFor(() => {
            expect({
              logs,
              types: eventEffects(control.types, setupTypes),
            }).toMatchObject({
              logs: expect.arrayContaining([
                expect.stringMatching(/reason=(invalid_policy|missing_policy|lifecycle_invalid)/),
              ]),
            });
          });
          expect(turns).toEqual([]);
          expect(eventEffects(control.types, setupTypes)).toEqual([]);
        } finally {
          abort.abort();
          await running.catch(() => undefined);
        }
      } finally {
        host.restoreState();
        await control.close();
        await rm(root, { recursive: true, force: true });
      }
    }
  });
});
