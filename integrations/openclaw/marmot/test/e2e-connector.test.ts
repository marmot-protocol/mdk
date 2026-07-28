import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
// Deliberate test-only internal import: openclaw@2026.7.1-2 exposes no supported
// plugin-loader subpath. Re-verify this path whenever the pinned SDK is bumped.
import {
  clearActivatedPluginRuntimeState,
  clearPluginLoaderCache,
  clearPluginRegistryLoadCache,
  loadOpenClawPlugins,
} from "../node_modules/openclaw/dist/plugins/loader.js";

import { MarmotAgentControlClient } from "../src/client.js";
import {
  createMarmotInboundDispatcher,
  type MarmotDispatchClient,
  type OpenClawChannelRuntime,
} from "../src/dispatch.js";
import {
  resetMarmotInboundAccountsForTests,
  startMarmotInbound,
  type InboundPluginApi,
} from "../src/inbound-runtime.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";

const RUN_CONNECTOR_E2E = process.env.MARMOT_OPENCLAW_CONNECTOR_E2E === "1";
const maybeDescribe = RUN_CONNECTOR_E2E ? describe : describe.skip;

const ACCOUNT_ID_HEX = "11".repeat(32);
const GROUP_ID_HEX = "22".repeat(32);
const SENDER_ACCOUNT_ID_HEX = "44".repeat(32);

interface DebugRecordedFinalSend {
  account_id_hex: string;
  group_id_hex: string;
  text: string;
  reply_to_message_id_hex?: string | null;
  message_ids_hex: string[];
}

interface DebugRecordedFinalsResponse {
  type: "debug_recorded_finals";
  sends: DebugRecordedFinalSend[];
}

function repoRoot(): string {
  return join(import.meta.dirname, "..", "..", "..", "..");
}

async function waitFor<T>(
  probe: () => Promise<T | null | undefined> | T | null | undefined,
  options: { timeoutMs?: number; intervalMs?: number; label?: string } = {},
): Promise<T> {
  const deadline = Date.now() + (options.timeoutMs ?? 30_000);
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await probe();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, options.intervalMs ?? 50));
  }
  const suffix = lastError instanceof Error ? `: ${lastError.message}` : "";
  throw new Error(`${options.label ?? "waitFor"} timed out${suffix}`);
}

async function stopProcess(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) {
    return;
  }
  proc.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolve) => proc.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (proc.exitCode === null && proc.signalCode === null) {
    proc.kill("SIGKILL");
  }
}

async function recordedFinals(
  client: MarmotAgentControlClient,
): Promise<DebugRecordedFinalsResponse> {
  return (await client.request({
    type: "debug_recorded_finals",
  })) as unknown as DebugRecordedFinalsResponse;
}

afterEach(() => {
  resetMarmotInboundAccountsForTests();
  resetMarmotInboundRuntimeForTests();
  clearActivatedPluginRuntimeState();
  clearPluginRegistryLoadCache();
  clearPluginLoaderCache();
});

maybeDescribe("OpenClaw Marmot connector E2E", () => {
  it(
    "keeps sequential and restarted inbound replies on the source Marmot group",
    async () => {
      const tempRoot = await mkdtemp("/tmp/omce-");
      const marmotHome = join(tempRoot, "marmot-home");
      const socketPath = join(tempRoot, "a.sock");
      const proc = spawn(
        "cargo",
        [
          "run",
          "-q",
          "-p",
          "agent-connector",
          "--bin",
          "wn-agent",
          "--",
          "--home",
          marmotHome,
          "--socket",
          socketPath,
          "--debug-controls",
        ],
        {
          cwd: repoRoot(),
          env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? "warn" },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      const stdout: string[] = [];
      const stderr: string[] = [];
      proc.stdout.on("data", (chunk) => stdout.push(String(chunk)));
      proc.stderr.on("data", (chunk) => stderr.push(String(chunk)));

      try {
        const client = new MarmotAgentControlClient({
          socketPath,
          requestTimeoutMs: 5_000,
        });
        await waitFor(
          async () => {
            await recordedFinals(client);
            return true;
          },
          { timeoutMs: 60_000, label: "wn-agent debug control socket" },
        );

        let readyCount = 0;
        const pluginRoot = join(import.meta.dirname, "..");
        const api: InboundPluginApi = {
          config: {
            plugins: {
              allow: ["marmot"],
              load: { paths: [pluginRoot] },
              entries: { marmot: { enabled: true } },
            },
            channels: {
              marmot: {
                socketPath,
                accountIdHex: ACCOUNT_ID_HEX,
                groupIdHex: GROUP_ID_HEX,
                profileNameOnboarding: false,
              },
            },
          },
          logger: {
            info: (message) => {
              if (message.includes("inbound subscription established")) {
                readyCount += 1;
              }
            },
            warn: () => {},
          },
        };

        // Load and activate the actual plugin so OpenClaw's production helper
        // resolves the registered Marmot message adapter and checks its declared
        // durable-final capabilities before sending.
        const registry = loadOpenClawPlugins({
          config: api.config as never,
          activationSourceConfig: api.config as never,
          workspaceDir: tempRoot,
          onlyPluginIds: ["marmot"],
          activate: true,
          loadModules: true,
          cache: false,
          mode: "full",
          throwOnLoadError: true,
        });
        expect(registry.channels.find((entry) => entry.plugin.id === "marmot")?.plugin.message)
          .toBeDefined();

        const runtimeChannel: OpenClawChannelRuntime = {
          routing: {
            resolveAgentRoute: () => ({
              agentId: "main",
              accountId: "default",
              sessionKey: `agent:main:marmot:group:${GROUP_ID_HEX}`,
            }),
          },
          session: {
            resolveStorePath: () => join(tempRoot, "sessions.json"),
            recordInboundSession: () => {},
          },
          reply: {
            dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
              const typed = params as {
                ctx: { MessageSid: string };
                dispatcherOptions: {
                  deliver: (
                    payload: { text: string },
                    info: { kind: "final" },
                  ) => Promise<void>;
                };
              };
              await typed.dispatcherOptions.deliver(
                { text: `marmot-e2e-ok:${typed.ctx.MessageSid.slice(0, 2)}` },
                { kind: "final" },
              );
            },
          },
        };
        const dispatch = createMarmotInboundDispatcher({
          cfg: api.config,
          runtimeChannel,
          client: client as unknown as MarmotDispatchClient,
          channelAccountId: "default",
          groupActivation: "always",
          mentionPatterns: [],
        });
        const runInbound = () =>
          startMarmotInbound(api, dispatch, {
            channelAccountId: "default",
            clientFactory: () => client,
          });

        let stopInbound = runInbound();
        try {
          await waitFor(() => readyCount === 1, { label: "initial inbound subscription" });
          const messageIds = ["a1", "a2", "a3"].map((byte) => byte.repeat(32));
          for (const messageIdHex of messageIds.slice(0, 2)) {
            await client.request({
              type: "debug_inject_inbound",
              account_id_hex: ACCOUNT_ID_HEX,
              group_id_hex: GROUP_ID_HEX,
              message_id_hex: messageIdHex,
              sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
              text: "ping from connector",
            });
          }
          await waitFor(async () => (await recordedFinals(client)).sends.length === 2, {
            label: "two sequential final sends",
          });

          stopInbound();
          stopInbound = runInbound();
          await waitFor(() => readyCount === 2, { label: "restarted inbound subscription" });
          await client.request({
            type: "debug_inject_inbound",
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            message_id_hex: messageIds[2]!,
            sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
            text: "ping after restart",
          });
          const finals = await waitFor(async () => {
            const recorded = await recordedFinals(client);
            return recorded.sends.length === 3 ? recorded.sends : null;
          }, { label: "post-restart final send" });

          expect(
            finals.map((send) => ({
              groupIdHex: send.group_id_hex,
              replyToId: send.reply_to_message_id_hex,
            })),
          ).toEqual(
            messageIds.map((messageIdHex) => ({
              groupIdHex: GROUP_ID_HEX,
              replyToId: messageIdHex,
            })),
          );
        } finally {
          stopInbound();
        }
      } catch (error) {
        const detail = [
          error instanceof Error ? error.message : String(error),
          stdout.length ? `stdout:\n${stdout.join("")}` : "",
          stderr.length ? `stderr:\n${stderr.join("")}` : "",
        ]
          .filter(Boolean)
          .join("\n\n");
        throw new Error(detail);
      } finally {
        await stopProcess(proc);
        await rm(tempRoot, { recursive: true, force: true });
      }
    },
    90_000,
  );
});
