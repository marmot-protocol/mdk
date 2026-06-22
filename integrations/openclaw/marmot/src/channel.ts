// The Marmot OpenClaw channel plugin definition.
//
// Composed with `createChatChannelPlugin`: meta + capabilities + a config
// adapter that resolves a Marmot account from the `channels.marmot` config (or
// MARMOT_* env), the durable/live message adapter, DM allowlist security, and
// reply threading. Outbound (durable send + live preview) flows through the
// message adapter; inbound is driven by src/inbound-runtime.ts.

import { jsonResult } from "openclaw/plugin-sdk/channel-actions";
import type {
  ChannelMessageActionAdapter,
  ChannelMessageActionContext,
} from "openclaw/plugin-sdk/channel-contract";
import {
  createChatChannelPlugin,
  type OpenClawConfig,
} from "openclaw/plugin-sdk/channel-core";
import {
  buildBaseChannelStatusSummary,
  collectStatusIssuesFromLastError,
  type ChannelAccountSnapshot,
} from "openclaw/plugin-sdk/status-helpers";

import { resolveSingleAccount } from "./account.js";
import {
  clientForAccount,
  marmotChannelConfigSchema,
  resolveMarmotAccount,
  type MarmotChannelAccountConfig,
  type ResolvedMarmotAccount,
} from "./config.js";
import { createMarmotMessagingAdapter } from "./messaging.js";
import { createMarmotMessageAdapter } from "./outbound.js";
import {
  DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
  marmotInboundRuntimeSnapshot,
} from "./runtime-state.js";

export const MARMOT_CHANNEL_ID = "marmot";

interface MarmotStatusProbe {
  ok: boolean;
  accounts: number;
  localSigningAccounts: number;
}

interface MarmotChannelsConfig {
  channels?: {
    marmot?: MarmotChannelAccountConfig & {
      accounts?: Record<string, MarmotChannelAccountConfig>;
    };
  };
}

function marmotSlice(cfg: OpenClawConfig): NonNullable<MarmotChannelsConfig["channels"]>["marmot"] {
  return (cfg as unknown as MarmotChannelsConfig).channels?.marmot ?? {};
}

/** Resolve a Marmot account for a (possibly multi-account) OpenClaw config. */
export function resolveMarmotChannelAccount(
  cfg: OpenClawConfig,
  accountId?: string | null,
): ResolvedMarmotAccount {
  const slice = marmotSlice(cfg);
  // Multi-account mode: every account (including "default") lives under
  // `channels.marmot.accounts.<id>`. Single-account mode: settings live on the
  // `channels.marmot` slice itself.
  if (slice?.accounts) {
    const selectedId = accountId ?? "default";
    const accountConfig = slice.accounts[selectedId];
    if (!accountConfig) {
      throw new Error(`unknown Marmot account id: ${selectedId}`);
    }
    return resolveMarmotAccount(accountConfig, selectedId);
  }
  return resolveMarmotAccount(slice, accountId ?? null);
}

function accountSnapshot(
  account: ResolvedMarmotAccount,
  runtime?: ChannelAccountSnapshot,
  probe?: unknown,
): ChannelAccountSnapshot {
  const accountId = account.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
  const inbound = marmotInboundRuntimeSnapshot(accountId);
  return {
    ...runtime,
    ...inbound,
    accountId,
    name: accountId,
    enabled: true,
    configured: true,
    running: inbound.running === true,
    connected: inbound.connected === true,
    lastStartAt: inbound.lastStartAt ?? runtime?.lastStartAt ?? null,
    lastStopAt: inbound.lastStopAt ?? runtime?.lastStopAt ?? null,
    lastError: inbound.lastError ?? runtime?.lastError ?? null,
    lastInboundAt: inbound.lastInboundAt ?? runtime?.lastInboundAt ?? null,
    lastOutboundAt: inbound.lastOutboundAt ?? runtime?.lastOutboundAt ?? null,
    reconnectAttempts: inbound.reconnectAttempts ?? runtime?.reconnectAttempts,
    mode: account.streamMode,
    dmPolicy: account.dmPolicy ?? "allowlist",
    allowFrom: account.allowFrom.map(String),
    probe,
  };
}

async function probeMarmotAccount(account: ResolvedMarmotAccount): Promise<MarmotStatusProbe> {
  const response = await clientForAccount(account).accountList();
  const localSigningAccounts = response.accounts.filter((entry) => entry.local_signing).length;
  return {
    ok: localSigningAccounts > 0,
    accounts: response.accounts.length,
    localSigningAccounts,
  };
}

/** Dependencies the channel-owned `delete` action adapter needs. */
export interface MarmotDeleteActionDeps {
  /** Resolve a sent message id to its group from the send-time cache. */
  deleteByMessageId: (
    targetMessageIdHex: string,
    resolveCtx: { cfg: unknown; accountId?: string | null },
  ) => Promise<boolean>;
  /** Resolve the dm-agent client + Marmot account for the explicit-group fallback. */
  resolveTarget: (
    cfg: unknown,
    accountId?: string | null,
  ) => Promise<{ client: MarmotMessageDeleteClient; marmotAccountIdHex: string }>;
}

/** Narrow view of the control client used by the explicit-group delete fallback. */
export interface MarmotMessageDeleteClient {
  deleteMessage: (
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
  ) => Promise<unknown>;
}

/**
 * Channel-owned `delete` action for the shared `message` tool: the agent's
 * `message(action:"delete", messageId, to)` reaches `handleAction`. Prefer the
 * send-time cache (no extra round-trip); fall back to an explicit `to` group.
 */
export function createMarmotDeleteActionAdapter(
  deps: MarmotDeleteActionDeps,
): ChannelMessageActionAdapter {
  return {
    describeMessageTool: () => ({ actions: ["delete"] }),
    handleAction: async (ctx: ChannelMessageActionContext) => {
      if (ctx.action !== "delete") {
        return jsonResult({ ok: false, error: `unsupported action: ${ctx.action}` });
      }
      const messageId = typeof ctx.params.messageId === "string" ? ctx.params.messageId : "";
      if (!messageId) {
        return jsonResult({ ok: false, error: "messageId required" });
      }
      if (await deps.deleteByMessageId(messageId, { cfg: ctx.cfg, accountId: ctx.accountId })) {
        return jsonResult({ ok: true, deleted: true });
      }
      const to = typeof ctx.params.to === "string" ? ctx.params.to : undefined;
      if (to) {
        const { client, marmotAccountIdHex } = await deps.resolveTarget(ctx.cfg, ctx.accountId ?? null);
        await client.deleteMessage(marmotAccountIdHex, to, messageId);
        return jsonResult({ ok: true, deleted: true });
      }
      return jsonResult({ ok: false, error: "could not resolve group for this message id" });
    },
  };
}

/** Build the Marmot channel plugin for registration with OpenClaw. */
export function createMarmotChannelPlugin() {
  // Resolve the dm-agent client + Marmot agent account for an outbound send or
  // an agent-invoked action (e.g. delete). Hoisted so both the message adapter
  // and the action adapter share one resolver.
  const resolveTarget = async (cfg: unknown, accountId?: string | null) => {
    const resolved = resolveMarmotChannelAccount(cfg as OpenClawConfig, accountId);
    const client = clientForAccount(resolved);
    const marmotAccountIdHex =
      resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
    return { client, marmotAccountIdHex };
  };

  // The durable/live message adapter. Captured in a const so the action adapter
  // can reuse its send-time conversation cache via `deleteByMessageId`.
  const messageAdapter = createMarmotMessageAdapter({ resolveTarget });

  const actions = createMarmotDeleteActionAdapter({
    deleteByMessageId: messageAdapter.deleteByMessageId,
    resolveTarget,
  });

  return createChatChannelPlugin<ResolvedMarmotAccount>({
    base: {
      id: MARMOT_CHANNEL_ID,
      meta: {
        id: MARMOT_CHANNEL_ID,
        label: "Marmot",
        selectionLabel: "Marmot",
        docsPath: "channels/marmot",
        blurb: "End-to-end encrypted Marmot groups through the local dm-agent connector.",
        markdownCapable: true,
      },
      capabilities: {
        chatTypes: ["direct", "group"],
        reply: true,
        media: true,
        blockStreaming: true,
        // Marmot supports deleting (unsending) a previously-sent message; gates
        // the agent-facing `delete` message action's visibility.
        unsend: true,
      },
      configSchema: marmotChannelConfigSchema(),
      config: {
        listAccountIds: (cfg) => {
          const accounts = marmotSlice(cfg)?.accounts;
          return accounts ? Object.keys(accounts) : ["default"];
        },
        resolveAccount: resolveMarmotChannelAccount,
      },
      status: {
        defaultRuntime: marmotInboundRuntimeSnapshot(DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID),
        collectStatusIssues: (accounts) => collectStatusIssuesFromLastError("marmot", accounts),
        buildChannelSummary: ({ snapshot }) =>
          buildBaseChannelStatusSummary(snapshot, {
            connected: snapshot.connected ?? null,
            mode: snapshot.mode ?? null,
            probe: snapshot.probe,
          }),
        probeAccount: async ({ account }) => probeMarmotAccount(account),
        buildAccountSnapshot: ({ account, runtime, probe }) =>
          accountSnapshot(account, runtime, probe),
      },
      message: messageAdapter,
      // Target resolution for the shared `message` tool: lets an agent-driven
      // send resolve a Marmot conversation (an MLS group id hex) instead of
      // erroring on an "unknown target" before the durable send runs.
      messaging: createMarmotMessagingAdapter(),
      // Steer the model away from guessing a `message`-tool target: a Marmot
      // reply is delivered automatically from the assistant's final text, and a
      // Marmot conversation is addressed by its group id hex (no @handles).
      agentPrompt: {
        messageToolHints: () => [
          "- Marmot replies: to answer the current conversation, just write your reply as normal assistant text — it is delivered to the Marmot group automatically. You do not need the `message` tool to reply.",
          "- Marmot `message` targets: a Marmot conversation is addressed by its group id hex (optionally prefixed `marmot:`). There are no @handles or #channels.",
        ],
      },
      actions,
    },
    security: {
      dm: {
        channelKey: MARMOT_CHANNEL_ID,
        resolvePolicy: (account) => account.dmPolicy ?? null,
        resolveAllowFrom: (account) => account.allowFrom,
        defaultPolicy: "allowlist",
      },
    },
    threading: {
      topLevelReplyToMode: "reply",
    },
  });
}
