import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChannelMessageSendTextContext } from "openclaw/plugin-sdk/channel-outbound";

import { MarmotAgentControlClient, AgentControlError } from "../src/client.js";
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
import type { MarmotInboundMessage } from "../src/inbound.js";
import { createMarmotMessageAdapter } from "../src/outbound.js";
import { resetMarmotInboundRuntimeForTests } from "../src/runtime-state.js";
import { MarmotTargetError } from "../src/target.js";

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

async function startWnAgent(tempRoot: string): Promise<{
  client: MarmotAgentControlClient;
  proc: ChildProcess;
  socketPath: string;
}> {
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
  proc.stdout?.resume();
  proc.stderr?.resume();
  const client = new MarmotAgentControlClient({
    socketPath,
    requestTimeoutMs: 5_000,
  });
  try {
    await waitFor(
      async () => {
        await recordedFinals(client);
        return true;
      },
      { timeoutMs: 120_000, label: "wn-agent debug control socket" },
    );
  } catch (error) {
    await stopProcess(proc);
    throw error;
  }
  return { client, proc, socketPath };
}

afterEach(() => {
  resetMarmotInboundRuntimeForTests();
  resetMarmotInboundAccountsForTests();
});

maybeDescribe("OpenClaw Marmot connector E2E", () => {
  it(
    "dispatches debug-injected inbound through the inbound runtime into real wn-agent send_final",
    async () => {
      const tempRoot = await mkdtemp("/tmp/omce-");
      const { client, proc, socketPath } = await startWnAgent(tempRoot);

      try {
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
          const finals = await waitFor(
            async () => {
              const recorded = await recordedFinals(client);
              return recorded.sends.find((send) => send.text === DETERMINISTIC_RESPONSE) ?? null;
            },
            { timeoutMs: 10_000, label: "recorded final send" },
          );
          expect(finals).toMatchObject({
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            text: DETERMINISTIC_RESPONSE,
            reply_to_message_id_hex: MESSAGE_ID_HEX,
            message_ids_hex: ["1".padStart(64, "0")],
          });
          expect(
            (await recordedFinals(client)).sends.filter((send) => send.text === DETERMINISTIC_RESPONSE),
          ).toHaveLength(1);
        } finally {
          stopInbound();
        }
      } finally {
        await stopProcess(proc);
        await rm(tempRoot, { recursive: true, force: true });
      }
    },
    90_000,
  );

  it(
    "canonical outbound targets, readiness retry, exact sequential finals, and same-process replay dedupe",
    async () => {
      const tempRoot = await mkdtemp("/tmp/omce-");
      const { client, proc, socketPath } = await startWnAgent(tempRoot);

      try {
        const adapter = createMarmotMessageAdapter({
          resolveTarget: async () => ({
            client,
            marmotAccountIdHex: ACCOUNT_ID_HEX,
          }),
        });
        for (const target of [GROUP_ID_HEX, `marmot:${GROUP_ID_HEX}`, `group:${GROUP_ID_HEX}`]) {
          await adapter.send!.text!({
            cfg: {},
            to: target,
            text: "canonical-target",
          } as ChannelMessageSendTextContext);
        }
        await expect(
          adapter.send!.text!({
            cfg: {},
            to: `agent:main:marmot:group:${GROUP_ID_HEX}`,
            text: "bad",
          } as ChannelMessageSendTextContext),
        ).rejects.toBeInstanceOf(MarmotTargetError);

        const readinessLogs: string[] = [];
        let groupInfoCalls = 0;
        const replyOptions: unknown[] = [];
        const runtimeChannel: OpenClawChannelRuntime = {
          routing: {
            resolveAgentRoute: () => ({
              agentId: "main",
              accountId: "default",
              sessionKey: "agent:main:marmot:group",
            }),
          },
          session: {
            resolveStorePath: () => join(tempRoot, "sessions.json"),
            recordInboundSession: vi.fn(),
          },
          reply: {
            dispatchReplyWithBufferedBlockDispatcher: async (params: unknown) => {
              const typed = params as {
                cfg: { tools?: { deny?: string[] } };
                replyOptions?: { sourceReplyDeliveryMode?: string };
                dispatcherOptions: {
                  deliver: (payload: { text?: string }, info: { kind: "final" }) => Promise<void>;
                };
              };
              replyOptions.push(typed.replyOptions ?? {});
              expect(typed.cfg.tools?.deny).toContain("sessions_send");
              // Same-process outbound adapter send inside the dispatch callback (not a
              // real OpenClaw shared-tool invocation) before the bound sink final.
              await adapter.send!.text!({
                cfg: {},
                accountId: "default",
                to: GROUP_ID_HEX,
                text: "adapter-owned-turn-reply",
              } as ChannelMessageSendTextContext);
              await typed.dispatcherOptions.deliver({ text: "bound-final" }, { kind: "final" });
            },
          },
        };
        const dispatchClient = Object.assign(client, {
          async groupInfo(accountIdHex: string, groupIdHex: string) {
            groupInfoCalls += 1;
            if (groupInfoCalls === 1) {
              throw new AgentControlError("group not ready yet", { retryable: true });
            }
            return {
              type: "group_info" as const,
              account_id_hex: accountIdHex,
              group_id_hex: groupIdHex,
              member_count: 2,
              is_direct: true,
              subject: null,
            };
          },
        }) as unknown as MarmotDispatchClient;
        const dispatch = createMarmotInboundDispatcher({
          cfg: { tools: { deny: ["exec"] } },
          runtimeChannel,
          client: dispatchClient,
          channelAccountId: "default",
          streamMode: "off",
          blockStreaming: false,
          quicCandidates: [],
          groupActivation: "always",
          mentionPatterns: [],
          log: (message) => readinessLogs.push(message),
        });

        let subscriptionReadyCount = 0;
        const api: InboundPluginApi = {
          config: {
            channels: {
              marmot: {
                socketPath,
                accountIdHex: ACCOUNT_ID_HEX,
                profileNameOnboarding: false,
              },
            },
          },
          logger: {
            info: (message) => {
              if (message.includes("inbound subscription established")) {
                subscriptionReadyCount += 1;
              }
            },
            warn: () => {},
          },
        };

        const delivered: MarmotInboundMessage[] = [];
        const runInbound = () =>
          startMarmotInbound(
            api,
            async (message) => {
              delivered.push(message);
              await dispatch(message);
            },
            { clientFactory: () => client },
          );

        let stopInbound = runInbound();
        try {
          await waitFor(() => subscriptionReadyCount === 1, {
            label: "initial inbound subscription readiness",
          });
          const messageIds = ["aa", "bb", "cc"].map((byte) => byte.repeat(32));
          for (const [idx, messageHex] of messageIds.entries()) {
            await client.request({
              type: "debug_inject_inbound",
              account_id_hex: ACCOUNT_ID_HEX,
              group_id_hex: GROUP_ID_HEX,
              message_id_hex: messageHex,
              sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
              text: `sequential-${idx + 1}`,
            });
            await waitFor(() => delivered.length === idx + 1);
            await waitFor(
              async () => {
                const recorded = await recordedFinals(client);
                return (
                  recorded.sends.filter(
                    (send) =>
                      send.text === "adapter-owned-turn-reply" &&
                      send.group_id_hex === GROUP_ID_HEX,
                  ).length ===
                  idx + 1
                );
              },
              { label: `sequential adapter-owned final ${idx + 1}` },
            );
            const turnFinals = (await recordedFinals(client)).sends.filter(
              (send) =>
                (send.text === "adapter-owned-turn-reply" || send.text === "bound-final") &&
                send.group_id_hex === GROUP_ID_HEX,
            );
            expect(turnFinals).toHaveLength(idx + 1);
            expect(turnFinals.every((send) => send.text === "adapter-owned-turn-reply")).toBe(true);
            const sourceReplies = turnFinals.filter(
              (send) => send.text === "adapter-owned-turn-reply",
            );
            expect(sourceReplies[idx]?.reply_to_message_id_hex).toBe(messageHex);
          }
          expect(replyOptions.at(-1)).toMatchObject({ sourceReplyDeliveryMode: "automatic" });
          expect(readinessLogs.some((line) => line.includes("readiness established after retry"))).toBe(
            true,
          );

          const finalsBeforeRestart = await recordedFinals(client);
          expect(
            finalsBeforeRestart.sends.filter(
              (send) => send.text === "adapter-owned-turn-reply" && send.group_id_hex === GROUP_ID_HEX,
            ),
          ).toHaveLength(3);
          expect(
            finalsBeforeRestart.sends.filter(
              (send) => send.text === "bound-final" && send.group_id_hex === GROUP_ID_HEX,
            ),
          ).toHaveLength(0);
          expect(
            finalsBeforeRestart.sends.filter(
              (send) => send.text === "canonical-target" && send.group_id_hex === GROUP_ID_HEX,
            ),
          ).toHaveLength(3);

          stopInbound();
          stopInbound = runInbound();
          await waitFor(() => subscriptionReadyCount === 2, {
            label: "restarted inbound subscription readiness",
          });
          await client.request({
            type: "debug_inject_inbound",
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            message_id_hex: messageIds[0]!,
            sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
            text: "replay",
          });
          const observationMessageId = "dd".repeat(32);
          await client.request({
            type: "debug_inject_inbound",
            account_id_hex: ACCOUNT_ID_HEX,
            group_id_hex: GROUP_ID_HEX,
            message_id_hex: observationMessageId,
            sender_account_id_hex: SENDER_ACCOUNT_ID_HEX,
            text: "post-replay observation",
          });
          // The subscription and same-group queue preserve order. Seeing this
          // later event complete proves the replay was observed before the
          // unchanged duplicate-count assertions below.
          await waitFor(
            () => delivered.some((message) => message.messageIdHex === observationMessageId),
            { label: "post-replay positive observation" },
          );
          await waitFor(
            async () =>
              (await recordedFinals(client)).sends.filter(
                (send) =>
                  send.text === "adapter-owned-turn-reply" &&
                  send.group_id_hex === GROUP_ID_HEX,
              ).length === 4,
            { label: "post-replay observation final" },
          );

          const finalsAfterReplay = await recordedFinals(client);
          expect(
            finalsAfterReplay.sends.filter(
              (send) => send.text === "adapter-owned-turn-reply" && send.group_id_hex === GROUP_ID_HEX,
            ),
          ).toHaveLength(4);
          expect(
            finalsAfterReplay.sends.filter(
              (send) => send.text === "bound-final" && send.group_id_hex === GROUP_ID_HEX,
            ),
          ).toHaveLength(0);
          expect(delivered.filter((message) => message.messageIdHex === messageIds[0])).toHaveLength(1);
        } finally {
          stopInbound();
        }
      } finally {
        await stopProcess(proc);
        await rm(tempRoot, { recursive: true, force: true });
      }
    },
    120_000,
  );

  it(
    "rejects regenerated text under a restart-stable key without duplicating durable sends",
    async () => {
      const tempRoot = await mkdtemp("/tmp/omce-restart-");
      const { client, proc, socketPath } = await startWnAgent(tempRoot);

      try {
        const inbound = {
          accountIdHex: ACCOUNT_ID_HEX,
          groupIdHex: GROUP_ID_HEX,
          messageIdHex: MESSAGE_ID_HEX,
          coalescedMessageIdsHex: [MESSAGE_ID_HEX],
        };
        const replyText = "restart-idempotency-reply";
        const childEnv = {
          ...process.env,
          MARMOT_E2E_SOCKET: socketPath,
          MARMOT_E2E_ACCOUNT: ACCOUNT_ID_HEX,
          MARMOT_E2E_GROUP: GROUP_ID_HEX,
          MARMOT_E2E_MESSAGE: MESSAGE_ID_HEX,
          MARMOT_E2E_REPLY: replyText,
          MARMOT_E2E_REPLAY_REPLY: "restart-idempotency-regenerated-reply",
        };
        const pluginRoot = join(import.meta.dirname, "..");
        const clientModule = join(pluginRoot, "dist/src/client.js");
        const idempotencyModule = join(pluginRoot, "dist/src/turn-idempotency.js");
        const commitChildScript = `
          import { createConnection } from "node:net";
          import { randomUUID } from "node:crypto";
          import { AGENT_CONTROL_PROTOCOL_V2 } from ${JSON.stringify(clientModule)};
          import { deriveTurnIdempotencyKeyFromInbound } from ${JSON.stringify(idempotencyModule)};
          const inbound = {
            accountIdHex: process.env.MARMOT_E2E_ACCOUNT,
            groupIdHex: process.env.MARMOT_E2E_GROUP,
            messageIdHex: process.env.MARMOT_E2E_MESSAGE,
            coalescedMessageIdsHex: [process.env.MARMOT_E2E_MESSAGE],
          };
          const key = deriveTurnIdempotencyKeyFromInbound(inbound);
          const envelope = {
            marmot_agent_control: AGENT_CONTROL_PROTOCOL_V2,
            id: randomUUID(),
            type: "send_final",
            account_id_hex: inbound.accountIdHex,
            group_id_hex: inbound.groupIdHex,
            text: process.env.MARMOT_E2E_REPLY,
            reply_to_message_id_hex: inbound.messageIdHex,
            idempotency_key: key,
          };
          await new Promise((resolve, reject) => {
            const socket = createConnection({ path: process.env.MARMOT_E2E_SOCKET });
            socket.once("error", reject);
            socket.once("connect", () => {
              const frame = Buffer.from(\`\${JSON.stringify(envelope)}\\n\`, "utf8");
              socket.write(frame, (err) => {
                if (err) {
                  reject(err);
                  return;
                }
                socket.end();
                resolve(undefined);
              });
            });
          });
          console.log(JSON.stringify({ key }));
        `;
        const replayChildScript = `
          import { MarmotAgentControlClient } from ${JSON.stringify(clientModule)};
          import { deriveTurnIdempotencyKeyFromInbound } from ${JSON.stringify(idempotencyModule)};
          const inbound = {
            accountIdHex: process.env.MARMOT_E2E_ACCOUNT,
            groupIdHex: process.env.MARMOT_E2E_GROUP,
            messageIdHex: process.env.MARMOT_E2E_MESSAGE,
            coalescedMessageIdsHex: [process.env.MARMOT_E2E_MESSAGE],
          };
          const key = deriveTurnIdempotencyKeyFromInbound(inbound);
          const client = new MarmotAgentControlClient({
            socketPath: process.env.MARMOT_E2E_SOCKET,
            requestTimeoutMs: 5_000,
          });
          try {
            await client.sendFinal(
              inbound.accountIdHex,
              inbound.groupIdHex,
              process.env.MARMOT_E2E_REPLAY_REPLY,
              inbound.messageIdHex,
              key,
            );
            console.log(JSON.stringify({ key, errorCode: null }));
          } catch (error) {
            console.log(JSON.stringify({ key, errorCode: error?.code ?? null }));
          }
        `;

        const runChild = <T>(script: string) =>
          new Promise<T>((resolve, reject) => {
            const child = spawn(
              process.execPath,
              ["--input-type=module", "-e", script],
              { env: childEnv, stdio: ["ignore", "pipe", "pipe"] },
            );
            let stdout = "";
            let stderr = "";
            child.stdout.on("data", (chunk) => {
              stdout += String(chunk);
            });
            child.stderr.on("data", (chunk) => {
              stderr += String(chunk);
            });
            child.on("error", reject);
            child.on("close", (code) => {
              if (code !== 0) {
                reject(new Error(`child exited ${code}: ${stderr}`));
                return;
              }
              try {
                resolve(JSON.parse(stdout.trim()) as T);
              } catch (error) {
                reject(new Error(`child output parse failed: ${stdout}\n${stderr}\n${error}`));
              }
            });
          });

        const matchesReply = (send: DebugRecordedFinalSend) =>
          send.text === replyText &&
          send.group_id_hex === GROUP_ID_HEX &&
          send.reply_to_message_id_hex === MESSAGE_ID_HEX;

        const { key: committedKey } = await runChild<{ key: string }>(commitChildScript);
        const committed = await waitFor(
          async () => {
            const finals = await recordedFinals(client);
            const matching = finals.sends.filter(matchesReply);
            const committedSend = matching[0];
            if (matching.length === 1 && committedSend && committedSend.message_ids_hex.length > 0) {
              return committedSend;
            }
            return null;
          },
          { label: "post-commit debug_recorded_finals", timeoutMs: 10_000 },
        );
        const committedMessageIdsHex = committed.message_ids_hex;

        const replay = await runChild<{ key: string; errorCode: string | null }>(replayChildScript);
        expect(replay.key).toBe(committedKey);
        expect(replay.errorCode).toBe("idempotency_conflict");

        const finals = await recordedFinals(client);
        expect(finals.sends.filter(matchesReply)).toHaveLength(1);
        expect(finals.sends.filter(matchesReply)[0]?.message_ids_hex).toEqual(committedMessageIdsHex);
        expect(
          finals.sends.filter((send) => send.text === childEnv.MARMOT_E2E_REPLAY_REPLY),
        ).toHaveLength(0);
      } finally {
        await stopProcess(proc);
        await rm(tempRoot, { recursive: true, force: true });
      }
    },
    120_000,
  );
});
