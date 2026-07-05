import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { MarmotAgentControlClient } from "../src/client.js";
import { startMarmotInbound, type InboundPluginApi } from "../src/inbound-runtime.js";
import type { MarmotInboundMessage } from "../src/inbound.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";

const RUN_CONNECTOR_E2E = process.env.MARMOT_OPENCLAW_CONNECTOR_E2E === "1";
const maybeDescribe = RUN_CONNECTOR_E2E ? describe : describe.skip;

const ACCOUNT_ID_HEX = "11".repeat(32);
const GROUP_ID_HEX = "22".repeat(32);
const MESSAGE_ID_HEX = "33".repeat(32);
const SENDER_ACCOUNT_ID_HEX = "44".repeat(32);
const INBOUND_TEXT = "ping from connector";
const DETERMINISTIC_RESPONSE = `marmot-e2e-ok: ${INBOUND_TEXT}`;

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
  const timeoutMs = options.timeoutMs ?? 30_000;
  const intervalMs = options.intervalMs ?? 50;
  const deadline = Date.now() + timeoutMs;
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
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
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
  resetMarmotInboundRuntimeForTests();
});

maybeDescribe("OpenClaw Marmot connector E2E", () => {
  it(
    "dispatches debug-injected inbound through the OpenClaw inbound runtime into real wn-agent send_final",
    async () => {
      // Keep the Unix socket path short for macOS sockaddr_un limits.
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

        let resolveReady: () => void = () => {};
        const ready = new Promise<void>((resolve) => {
          resolveReady = resolve;
        });
        let resolveDispatched: (message: MarmotInboundMessage) => void = () => {};
        const dispatched = new Promise<MarmotInboundMessage>((resolve) => {
          resolveDispatched = resolve;
        });
        const api: InboundPluginApi = {
          config: {
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
                resolveReady();
              }
            },
            warn: () => {},
          },
        };

        const stopInbound = startMarmotInbound(
          api,
          async (message) => {
            await client.sendFinal(
              message.accountIdHex,
              message.groupIdHex,
              DETERMINISTIC_RESPONSE,
              message.messageIdHex,
            );
            resolveDispatched(message);
          },
          { clientFactory: () => client },
        );

        try {
          await ready;
          await client.request({
            type: "debug_inject_inbound",
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            message_id_hex: MESSAGE_ID_HEX,
            sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
            text: INBOUND_TEXT,
          });

          await expect(dispatched).resolves.toMatchObject({
            accountIdHex: ACCOUNT_ID_HEX,
            groupIdHex: GROUP_ID_HEX,
            messageIdHex: MESSAGE_ID_HEX,
            senderAccountIdHex: SENDER_ACCOUNT_ID_HEX,
            text: INBOUND_TEXT,
          });
          const final = await waitFor(
            async () => {
              const recorded = await recordedFinals(client);
              return recorded.sends[0] ?? null;
            },
            { timeoutMs: 10_000, label: "recorded final send" },
          );
          expect(final).toMatchObject({
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            text: DETERMINISTIC_RESPONSE,
            reply_to_message_id_hex: MESSAGE_ID_HEX,
            message_ids_hex: ["1".padStart(64, "0")],
          });
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
