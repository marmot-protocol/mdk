// The Marmot OpenClaw channel plugin definition.
//
// Composed with `createChatChannelPlugin`: meta + capabilities + a config
// adapter that resolves a Marmot account from the `channels.marmot` config (or
// MARMOT_* env), the durable message adapter, gateway-owned inbound lifecycle,
// DM allowlist security, and reply threading.

import type {
  ChannelMessageActionAdapter,
  ChannelMessageActionContext,
} from "openclaw/plugin-sdk/channel-contract";
import {
  createChatChannelPlugin,
  jsonResult,
  type OpenClawConfig,
} from "openclaw/plugin-sdk/core";
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
import { startMarmotGatewayAccount } from "./gateway.js";
import { AgentControlError } from "./client.js";
import { createMarmotMessagingAdapter, normalizeMarmotTarget } from "./messaging.js";
import { createMarmotMessageAdapter } from "./outbound.js";
import {
  DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID,
  marmotInboundRuntimeSnapshot,
  marmotSenderAuthorizerLifecycle,
  marmotSenderPolicyState,
} from "./runtime-state.js";
import { senderPolicyErrorCode, senderPolicyIsReady } from "./sender-policy.js";

export const MARMOT_CHANNEL_ID = "marmot";

interface MarmotStatusProbe {
  ok: boolean;
  accounts: number;
  localSigningAccounts: number;
  senderPolicyState?: string;
  senderPolicyAllowedUserCount?: number;
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

/** Selected channel-account config before connection/token-file resolution. */
export interface SelectedMarmotChannelAccount {
  accountId: string | null;
  config: MarmotChannelAccountConfig;
}

/**
 * Share the existing single/multi-account selection logic without resolving
 * sockets, tokens, or other connection material. Unknown configured accounts
 * still fail closed.
 */
export function selectMarmotChannelAccountConfig(
  cfg: OpenClawConfig,
  accountId?: string | null,
): SelectedMarmotChannelAccount {
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
    return { accountId: selectedId, config: accountConfig };
  }
  return { accountId: accountId ?? null, config: slice ?? {} };
}

/** Resolve a Marmot account for a (possibly multi-account) OpenClaw config. */
export function resolveMarmotChannelAccount(
  cfg: OpenClawConfig,
  accountId?: string | null,
): ResolvedMarmotAccount {
  const selected = selectMarmotChannelAccountConfig(cfg, accountId);
  return resolveMarmotAccount(selected.config, selected.accountId);
}

function accountSnapshot(
  account: ResolvedMarmotAccount,
  runtime?: ChannelAccountSnapshot,
  probe?: unknown,
): ChannelAccountSnapshot {
  const accountId = account.accountId ?? DEFAULT_MARMOT_CHANNEL_ACCOUNT_ID;
  const fallback = marmotInboundRuntimeSnapshot(accountId);
  // Prefer a supplied host runtime, including a deliberate `lastError: null`.
  // Do not overlay the compatibility snapshot or resurrect stale errors.
  // The lifecycle-bound policy facts are authoritative while the account runs.
  // Re-resolving configuration here would make environment changes appear to
  // take effect before the documented gateway restart.
  const source = runtime ?? fallback;
  const senderPolicy = marmotSenderPolicyState(accountId) ?? "pending";
  const policyError = senderPolicyErrorCode(senderPolicy);
  const senderReady =
    senderPolicyIsReady(senderPolicy) && marmotSenderAuthorizerLifecycle(accountId) === "active";
  return {
    accountId,
    name: accountId,
    enabled: true,
    configured: true,
    running: source.running === true,
    connected: senderReady && source.connected === true,
    lastStartAt: source.lastStartAt ?? null,
    lastStopAt: source.lastStopAt ?? null,
    lastError: source.lastError ?? policyError ?? null,
    lastInboundAt: source.lastInboundAt,
    lastOutboundAt: source.lastOutboundAt,
    reconnectAttempts: source.reconnectAttempts,
    mode: "off",
    dmPolicy: account.dmPolicy ?? "allowlist",
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
    senderPolicyState: account.senderPolicy.state,
    senderPolicyAllowedUserCount: account.senderPolicy.allowedUserCount,
  };
}

/** Dependencies the channel-owned message action adapter needs. */
export interface MarmotMessageActionDeps {
  /** Look up where a message this adapter sent went, without mutating anything. */
  sentTargetFor?: (
    messageIdHex: string,
  ) => { marmotAccountIdHex: string; groupIdHex: string } | undefined;
  /** Resolve the wn-agent client + Marmot account for a message mutation. */
  resolveTarget: (
    cfg: unknown,
    accountId?: string | null,
  ) => Promise<{ client: MarmotMessageActionClient; marmotAccountIdHex: string }>;
}

/** Narrow view of the control client used by message mutations. */
export interface MarmotMessageActionClient {
  deleteMessage: (
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
  ) => Promise<unknown>;
  editMessage: (
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
    text: string,
  ) => Promise<unknown>;
  sendReaction: (
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
    emoji: string,
  ) => Promise<unknown>;
  removeReaction: (
    accountIdHex: string,
    groupIdHex: string,
    targetMessageIdHex: string,
    emoji?: string,
  ) => Promise<unknown>;
}

/**
 * Channel-owned `delete`, `edit` and `react` actions for the shared `message`
 * tool: the agent's `message(action:"delete", messageId, to)` reaches
 * `handleAction`. Delete and edit stay in the host-authorized conversation; see
 * {@link resolveAuthorizedSentTarget}.
 */
export function createMarmotMessageActionAdapter(
  deps: MarmotMessageActionDeps,
): ChannelMessageActionAdapter {
  return {
    describeMessageTool: () => ({ actions: ["delete", "edit", "react"] }),
    supportsAction: ({ action }) =>
      action === "delete" || action === "edit" || action === "react",
    handleAction: async (ctx: ChannelMessageActionContext) => {
      if (ctx.action === "edit") {
        return handleEditAction(ctx, deps);
      }
      if (ctx.action === "react") {
        const messageId =
          typeof ctx.params.messageId === "string"
            ? ctx.params.messageId
            : typeof ctx.params.message_id === "string"
              ? ctx.params.message_id
            : String(ctx.toolContext?.currentMessageId ?? "");
        // The send-time cache only knows messages this agent sent, so it cannot
        // route a reaction to someone else's message. Current inbound reactions
        // inherit the tool context, while reactions to an earlier outbound
        // message therefore require an explicit `to`.
        const rawTo =
          typeof ctx.params.to === "string"
            ? ctx.params.to
            : ctx.toolContext?.currentMessagingTarget;
        const to = normalizeMarmotTarget(rawTo ?? "");
        if (!messageId) {
          return jsonResult({
            ok: false,
            error: "messageId required. Provide messageId explicitly or react to the current inbound message.",
          });
        }
        if (!to) {
          return jsonResult({ ok: false, error: "could not resolve group for this message id" });
        }
        const remove = ctx.params.remove === true;
        if (ctx.params.emoji !== undefined && typeof ctx.params.emoji !== "string") {
          return jsonResult({ ok: false, error: "emoji must be a string" });
        }
        const emoji = typeof ctx.params.emoji === "string" ? ctx.params.emoji : "";
        if (!remove && emoji.length === 0) {
          return jsonResult({ ok: false, error: "emoji required unless remove is true" });
        }
        try {
          const { client, marmotAccountIdHex } = await deps.resolveTarget(
            ctx.cfg,
            ctx.accountId ?? null,
          );
          if (remove) {
            if (emoji.length > 0) {
              await client.removeReaction(marmotAccountIdHex, to, messageId, emoji);
            } else {
              await client.removeReaction(marmotAccountIdHex, to, messageId);
            }
            return jsonResult({ ok: true, removed: true });
          }
          await client.sendReaction(marmotAccountIdHex, to, messageId, emoji);
          return jsonResult({ ok: true, added: emoji });
        } catch (error) {
          if (
            remove &&
            error instanceof AgentControlError &&
            error.code === "reaction_not_found"
          ) {
            return jsonResult({ ok: true, removed: true });
          }
          return jsonResult({ ok: false, error: "reaction operation failed" });
        }
      }
      if (ctx.action !== "delete") {
        return jsonResult({ ok: false, error: `unsupported action: ${ctx.action}` });
      }
      return handleDeleteAction(ctx, deps);
    },
  };
}

/**
 * Resolve the group a delete or edit of `messageId` may act in. The host checks
 * cross-context policy against the explicit `to` group, and a turn is bound to
 * its current conversation, so that group always wins; the send-time cache only
 * fills in a missing target, and a cached message from a different group is
 * refused rather than mutated there. The host does not infer `to` for a
 * targetless edit, and a bound Marmot turn carries its group on
 * `currentChannelId`: Marmot has no threading hook, so the host never sets
 * `currentMessagingTarget` for it.
 */
function resolveAuthorizedSentTarget(
  ctx: ChannelMessageActionContext,
  deps: MarmotMessageActionDeps,
  messageId: string,
): { groupIdHex: string; cachedAccountIdHex?: string } | { error: string } {
  // The host treats a blank `to` as absent, so skip blanks rather than let one
  // hide the binding. A present target that is not a Marmot group is refused,
  // never replaced by the cache.
  const rawTo = [
    ctx.params.to,
    ctx.toolContext?.currentMessagingTarget,
    ctx.toolContext?.currentChannelId,
  ].find((value): value is string => typeof value === "string" && value.trim().length > 0);
  const authorized = rawTo === undefined ? undefined : normalizeMarmotTarget(rawTo);
  if (rawTo !== undefined && !authorized) {
    return { error: `${ctx.action} target is not a Marmot conversation` };
  }
  const cached = deps.sentTargetFor?.(messageId);
  if (authorized && cached && cached.groupIdHex.toLowerCase() !== authorized) {
    return {
      error: `this message was sent to a different conversation than the ${ctx.action} target`,
    };
  }
  const groupIdHex = authorized || cached?.groupIdHex;
  if (!groupIdHex) {
    return { error: "could not resolve group for this message id" };
  }
  return { groupIdHex, cachedAccountIdHex: cached?.marmotAccountIdHex };
}

/** Channel-owned `delete` action for a message this agent sent. */
async function handleDeleteAction(
  ctx: ChannelMessageActionContext,
  deps: MarmotMessageActionDeps,
) {
  const messageId = typeof ctx.params.messageId === "string" ? ctx.params.messageId : "";
  if (!messageId) {
    return jsonResult({ ok: false, error: "messageId required" });
  }
  const target = resolveAuthorizedSentTarget(ctx, deps, messageId);
  if ("error" in target) {
    return jsonResult({ ok: false, error: target.error });
  }
  const { client, marmotAccountIdHex } = await deps.resolveTarget(ctx.cfg, ctx.accountId ?? null);
  await client.deleteMessage(
    target.cachedAccountIdHex ?? marmotAccountIdHex,
    target.groupIdHex,
    messageId,
  );
  return jsonResult({ ok: true, deleted: true });
}

/**
 * Channel-owned `edit` action: `message(action:"edit", messageId, message)`
 * replaces the text of a chat message this agent sent, keeping its place in the
 * conversation (for example a status line updated as work progresses). The
 * target group is resolved by {@link resolveAuthorizedSentTarget}.
 */
async function handleEditAction(
  ctx: ChannelMessageActionContext,
  deps: MarmotMessageActionDeps,
) {
  const messageId =
    typeof ctx.params.messageId === "string"
      ? ctx.params.messageId
      : typeof ctx.params.message_id === "string"
        ? ctx.params.message_id
        : "";
  if (!messageId) {
    return jsonResult({ ok: false, error: "messageId required" });
  }
  const text =
    typeof ctx.params.message === "string"
      ? ctx.params.message
      : typeof ctx.params.text === "string"
        ? ctx.params.text
        : undefined;
  if (text === undefined || text.trim().length === 0) {
    return jsonResult({ ok: false, error: "message required: the replacement text" });
  }
  const target = resolveAuthorizedSentTarget(ctx, deps, messageId);
  if ("error" in target) {
    return jsonResult({ ok: false, error: target.error });
  }
  try {
    const { client, marmotAccountIdHex } = await deps.resolveTarget(
      ctx.cfg,
      ctx.accountId ?? null,
    );
    await client.editMessage(
      target.cachedAccountIdHex ?? marmotAccountIdHex,
      target.groupIdHex,
      messageId,
      text,
    );
    return jsonResult({ ok: true, edited: true });
  } catch (error) {
    if (error instanceof AgentControlError && error.code === "invalid_edit_target") {
      return jsonResult({
        ok: false,
        error: "only an available message this agent sent can be edited",
      });
    }
    return jsonResult({ ok: false, error: "edit failed" });
  }
}

/** Build the Marmot channel plugin for registration with OpenClaw. */
export function createMarmotChannelPlugin() {
  // Resolve the wn-agent client + Marmot agent account for an outbound send or
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
  // can look up its send-time conversation cache via `sentTargetFor`.
  const messageAdapter = createMarmotMessageAdapter({ resolveTarget });

  const actions = createMarmotMessageActionAdapter({
    sentTargetFor: (messageIdHex) => messageAdapter.sentTargets.get(messageIdHex),
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
        blurb: "End-to-end encrypted Marmot groups through the local wn-agent connector.",
        markdownCapable: true,
      },
      capabilities: {
        chatTypes: ["direct", "group"],
        reply: true,
        media: true,
        blockStreaming: false,
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
          "- Marmot history: use `marmot_history` with the conversation group id when you need an exact durable message id, one referenced message, or an older transcript page.",
        ],
      },
      actions,
      gateway: {
        startAccount: startMarmotGatewayAccount,
      },
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
